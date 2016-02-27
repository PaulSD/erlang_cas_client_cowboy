%%%-------------------------------------------------------------------------------------------------
%%%
%%% Copyright 2013 Paul Donohue <erlang_cas_client_cowboy@PaulSD.com>
%%%
%%% This file is part of erlang_cas_client_cowboy.
%%%
%%% erlang_cas_client_cowboy is free software: you can redistribute it and/or modify it under the
%%% terms of the GNU Lesser General Public License as published by the Free Software Foundation,
%%% either version 3 of the License, or (at your option) any later version.
%%%
%%% erlang_cas_client_cowboy is distributed in the hope that it will be useful, but WITHOUT ANY
%%% WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
%%% PURPOSE.  See the GNU Lesser General Public License for more details.
%%%
%%% You should have received a copy of the GNU Lesser General Public License along with
%%% erlang_cas_client_cowboy.  If not, see {http://www.gnu.org/licenses/}.
%%%
%%%-------------------------------------------------------------------------------------------------

%% @doc CAS Client Middleware for Cowboy
-module(cowboy_cas_client).

-export([client_cookies_enabled/1, user/1, attribute/2, attributes/1, proxy_ticket/2]).

-behaviour(cowboy_middleware).
-export([execute/2]).

-define(CAS_KEY, cas_attributes).
-define(COOKIE_KEY, cookies_enabled).
-define(GATEWAYED_PARAM, <<"cas_gateway">>).
-define(RETRIES_PARAM, <<"cas_retry">>).
-define(COOKIE_PARAM, <<"cas_cookie">>).



%%%=================================================================================================
%%% Public API

%% @doc Return a boolean indicating whether the client has cookies enabled.
-spec client_cookies_enabled(Req) -> {boolean(), Req} when Req::cowboy_req:req().
client_cookies_enabled(Req) -> cowboy_req:meta(?COOKIE_KEY, Req).

%% @doc Return the CAS authenticated user name associated with the specified request.  Returns
%% 'not_authenticated' if the request has not been CAS authenticated.
-spec user(Req) -> {not_authenticated | binary(), Req} when Req::cowboy_req:req().
user(Req1) ->
  {Attrs, Req} = attributes(Req1),
  {cas_client_core:user(Attrs), Req}.

%% @doc Return the value of the specified CAS attribute associated with the specified request.
%% Returns 'not_authenticated' if the request has not been CAS authenticated, or 'undefined' if the
%% requested attribute was not returned by CAS.
-spec attribute(Key, Req) -> {not_authenticated | Value | undefined, Req}
  when Req::cowboy_req:req(), Key::binary(), Value::binary().
attribute(Key, Req1) ->
  {Attrs, Req} = attributes(Req1),
  {cas_client_core:attribute(Key, Attrs), Req}.

%% @doc Return a proplist containing the CAS attributes associated with the specified request, or
%% 'not_authenticated' if the request has not been CAS authenticated.
-spec attributes(Req) -> {cas_client_core:attributes(), Req} when Req::cowboy_req:req().
attributes(Req) -> cowboy_req:meta(?CAS_KEY, Req).

%% @doc Return a CAS Proxy Ticket associated with the specified Service URL for the authenticated
%% user associated with the specified request.  Returns 'not_authenticated' if the attributes
%% indicate no CAS authentication.  Returns 'undefined' if there is no PGT associated with the
%% authenticated user.  Returns 'retry' if a "soft" error occurred but the caller may try again (the
%% caller should limit the number of times it attempts to retry).  Returns 'error' if a "hard" error
%% occurred and the caller should not try again.
-spec proxy_ticket(ServiceURL, Req) ->
  {not_authenticated | undefined | {ok, Ticket} | retry | error, Req}
  when Req::cowboy_req:req(), ServiceURL::binary(), Ticket::binary().
proxy_ticket(ServiceURL, Req1) ->
  {Attrs, Req} = attributes(Req1),
  {cas_client_core:proxy_ticket(ServiceURL, Attrs, fun(K) -> core_config(K, Req) end), Req}.



%%%=================================================================================================
%%% cowboy_middleware API

%% @private
-spec execute(Req, Env) -> {ok, Req, Env} | {halt, Req} | {error, cowboy:http_status(), Req}
  when Req::cowboy_req:req(), Env::cowboy_middleware:env().
execute(Req1, Env) ->
  Req2 = cowboy_req:set_meta(cas_client_core, proplists:get_value(cas_client_core, Env), Req1),
  Req3 = cowboy_req:set_meta(cas_client_cowboy, proplists:get_value(cas_client_cowboy, Env), Req2),
  {Ticket, Req4} = cowboy_req:qs_val(<<"ticket">>, Req3),
  {GatewayedParam, Req5} = cowboy_req:qs_val(?GATEWAYED_PARAM, Req4),
  Gatewayed = case GatewayedParam of undefined -> false; _ -> true end,
  {RetriesParam, Req6} = cowboy_req:qs_val(?RETRIES_PARAM, Req5),
  Retries = case catch {ok, binary_to_integer(RetriesParam)} of {ok, R} -> R; _ -> 0 end,
  {CookieTestParam, Req7} = cowboy_req:qs_val(?COOKIE_PARAM, Req6),
  CookieTest = case CookieTestParam of undefined -> false; _ -> true end,
  {PGTiou, Req8} = cowboy_req:qs_val(<<"pgtIou">>, Req7),
  {PGT, Req9} = cowboy_req:qs_val(<<"pgtId">>, Req8),
  {ReadPGT, Req10} =
    case PGTiou =/= undefined andalso PGT =/= undefined of
    true ->
      {PGTURL, Req9a} = pgt_url(Req9),
      {PGTURL =:= core_config(pgt_callback_url, Req9a), Req9a};
    false -> {false, Req9}
    end,
  {Path, Req} = cowboy_req:path(Req10),
  case {ReadPGT, (Path =:= cowboy_config(logout_path, Req))} of
  {true, _} ->  %% Handle PGT Callback from CAS
    cas_client_core:pgt_iou(PGTiou, PGT),
    {ok, ReqA} = cowboy_req:reply(200, Req),
    {halt, ReqA};
  {_, true} ->  %% Handle Logout request
    Attrs = giallo_session:get(?CAS_KEY, Req),
    lager:debug("Logging out user with CAS attributes ~p", [Attrs]),
    giallo_session:clear(Req),
    reply_redirect(cas_client_core:logout_url(undefined, fun(K) -> core_config(K, Req) end), Req);
  _ ->
    SessionExists = giallo_session:exists(Req),
    case Ticket of
    undefined ->
      case {Gatewayed, core_config(gateway, Req), SessionExists, giallo_session:get(?CAS_KEY, Req), CookieTest} of
      {false, _, false, _, _} ->
        lager:debug("No established session or CAS parameters, redirecting to CAS for authentication"),
        ReqA = giallo_session:new(Req),
        {URL, ReqB} = login_return_url(ReqA),
        reply_redirect(cas_client_core:login_url(URL, fun(K) -> core_config(K, ReqB) end), ReqB);
      {true, false, false, _, _} ->
        lager:warning("Bogus ~s query parameter in request (will ignore)", [?GATEWAYED_PARAM]),
        lager:debug("No established session or CAS parameters, redirecting to CAS for authentication"),
        ReqA = giallo_session:new(Req),
        {URL, ReqB} = login_return_url(ReqA),
        reply_redirect(cas_client_core:login_url(URL, fun(K) -> core_config(K, ReqB) end), ReqB);
      {false, _, true, undefined, _} ->
        lager:debug("No established authentication or CAS parameters, redirecting to CAS for authentication"),
        {URL, ReqA} = login_return_url(Req),
        reply_redirect(cas_client_core:login_url(URL, fun(K) -> core_config(K, ReqA) end), ReqA);
      {true, false, true, undefined, _} ->
        lager:warning("Bogus ~s query parameter in request (will ignore)", [?GATEWAYED_PARAM]),
        lager:debug("No established authentication or CAS parameters, redirecting to CAS for authentication"),
        {URL, ReqA} = login_return_url(Req),
        reply_redirect(cas_client_core:login_url(URL, fun(K) -> core_config(K, ReqA) end), ReqA);
      {false, _, true, Attrs, _} ->
        ReqA = cowboy_req:set_meta(?CAS_KEY, Attrs, Req),
        ReqB = cowboy_req:set_meta(?COOKIE_KEY, true, ReqA),
        lager:debug("Using previously established CAS authentication ~p", [Attrs]),
        {ok, ReqB, Env};
      {true, false, true, _, _} ->
        lager:warning("Bogus ~s query parameter in request (will remove)", [?GATEWAYED_PARAM]),
        {URL, ReqA} = clean_url(Req), reply_redirect(URL, ReqA);
      {true, true, false, _, false} ->
        %% A session should have been created when the user was redirected to CAS, so it is possible
        %% that Cookies are disabled.  However, there are a few situations in which this could occur
        %% when Cookies are enabled, for example if the CAS server displays an advisory page before
        %% redirecting an authenticated user to the application and the user has bookmarked that
        %% advisory page.  Perform a redirect with a query parameter to definitively test whether
        %% Cookies are disabled.
        {LogURL, ReqA} = url(Req),
        lager:debug("No session for request to ~s, testing for disabled cookies", [LogURL]),
        ReqB = giallo_session:new(ReqA),
        {URL, ReqC} = cookie_test_url(ReqB), reply_redirect(URL, ReqC);
      {true, true, _, _, _} ->  %% Gateway auth, user not logged in to CAS
        lager:debug("Accepting unauthenticated (CAS gateway) request"),
        ReqA = cowboy_req:set_meta(?CAS_KEY, not_authenticated, Req),
        ReqB = cowboy_req:set_meta(?COOKIE_KEY, SessionExists, ReqA),
        case SessionExists of
        true ->  %% Cookies are enabled, redirect to remove the CAS query parameters
          case giallo_session:get(?CAS_KEY, ReqB) of
          undefined -> ok;
          Attrs -> lager:info("Replacing existing CAS authentication ~p with ~p", [Attrs, not_authenticated])
          end,
          giallo_session:set(?CAS_KEY, not_authenticated, ReqB),
          {URL, ReqC} = clean_url(ReqB), reply_redirect(URL, ReqC);
        false ->  %% Cookies are disabled, redirecting would cause a redirect loop through CAS
          {LogURL, ReqC} = url(ReqB),
          lager:debug("Received request to ~s with cookies disabled", [LogURL]),
          {ok, ReqC, Env}
        end
      end;
    _ ->  %% CAS Ticket is present
      case {SessionExists, CookieTest} of
      {false, false} ->
        %% A session should have been created when the user was redirected to CAS, so it is possible
        %% that Cookies are disabled.  However, there are a few situations in which this could occur
        %% when Cookies are enabled, for example if the user bookmarked the CAS login page.  Perform
        %% a redirect with a query parameter to definitively test whether Cookies are disabled.
        {LogURL, ReqA} = url(Req),
        lager:debug("No session for request to ~s, testing for disabled cookies", [LogURL]),
        ReqB = giallo_session:new(ReqA),
        {URL, ReqC} = cookie_test_url(ReqB), reply_redirect(URL, ReqC);
      _ ->
        {ServiceURL, ReqA} = ticket_service_url(Req),
        case cas_client_core:validate(Ticket, ServiceURL, fun(K) -> core_config(K, ReqA) end) of
        {ok, CAS_Attributes} ->
          ReqB = cowboy_req:set_meta(?CAS_KEY, CAS_Attributes, ReqA),
          ReqC = cowboy_req:set_meta(?COOKIE_KEY, SessionExists, ReqB),
          case SessionExists of
          true ->  %% Cookies are enabled, redirect to remove the CAS query parameters
            case giallo_session:get(?CAS_KEY, ReqC) of
            undefined -> ok;
            Attrs -> lager:info("Replacing existing CAS authentication ~p with ~p", [Attrs, CAS_Attributes])
            end,
            giallo_session:set(?CAS_KEY, CAS_Attributes, ReqC),
            {URL, ReqD} = clean_url(ReqC), reply_redirect(URL, ReqD);
          false ->  %% Cookies are disabled, redirecting would cause a redirect loop through CAS
            {LogURL, ReqD} = url(ReqC),
            lager:debug("Received request to ~s with cookies disabled", [LogURL]),
            {ok, ReqD, Env}
          end;
        retry ->
          MaxAttempts = core_config(max_validate_attempts, ReqA),
          if
          Retries + 1 < MaxAttempts ->
            lager:warning("Soft failure authenticating CAS Ticket ~s (Will try again)", [Ticket]),
            {URL, ReqB} = retry_return_url(ReqA, Retries + 1),
            reply_redirect(cas_client_core:login_url(URL, fun(K) -> core_config(K, ReqB) end), ReqB);
          true ->
            lager:error("Soft failure authenticating CAS Ticket ~s (Giving up after too many failed attempts)", [Ticket]),
            reply_error(500, <<"Authentication error occurred">>, ReqA)
          end;
        error ->
          lager:error("Hard failure authenticating CAS Ticket ~s", [Ticket]),
          reply_error(500, <<"Authentication error occurred">>, ReqA)
        end
      end
    end
  end.



%%%=================================================================================================
%%% Private Functions

%% @private
%% @doc Read the specified configuration value from the 'cas_client_core' value in the Cowboy
%% middleware environment, or from the 'cas_client_core' application environment.
-spec core_config(Key, Req) -> Value when Req::cowboy_req:req(), Key::atom(), Value::any().
core_config(Key, Req) ->
  case cowboy_req:meta(cas_client_core, Req) of
  {undefined, _Req1} -> cas_client_core_config:get(Key);
  {Config, _Req1} ->
    case proplists:get_value(Key, Config) of
    undefined -> cas_client_core_config:get(Key);
    Value ->
      %% We don't have a way to validate configuration options specified in the middleware
      %% environment at start, so validate them at run time
      case cas_client_core_config:validate(Key, Value) of
      {error, Message} ->
        lager:error("~s", [Message]),
        cas_client_core_config:get(Key);
      ok -> Value
      end
    end
  end.

%% @private
%% @doc Read the specified configuration value from the 'cas_client_cowboy' value in the Cowboy
%% middleware environment, or from the 'cas_client_cowboy' application environment.
-spec cowboy_config(Key, Req) -> Value when Req::cowboy_req:req(), Key::atom(), Value::any().
cowboy_config(Key, Req) ->
  case cowboy_req:meta(cas_client_cowboy, Req) of
  {undefined, _Req1} -> cas_client_cowboy_config:get(Key);
  {Config, _Req1} ->
    case proplists:get_value(Key, Config) of
    undefined -> cas_client_cowboy_config:get(Key);
    Value ->
      %% We don't have a way to validate configuration options specified in the middleware
      %% environment at start, so validate them at run time
      case cas_client_cowboy_config:validate(Key, Value) of
      {error, Message} ->
        lager:error("~s", [Message]),
        cas_client_cowboy_config:get(Key);
      ok -> Value
      end
    end
  end.

%% @private
%% @doc Convenience function for returning an error message.
-spec reply_error(cowboy:http_status(), Message, Req) -> {halt, Req}
  when Req::cowboy_req:req(), Message::binary().
reply_error(Status, Message, Req) ->
  Req1 = cowboy_req:set_resp_header(<<"content-type">>, <<"text/html">>, Req),
  Body = <<"<html>\n<head><title>Error</title></head>\n<body>\n<h1>Error: ", Message/binary,
    "</h1>\n</body>\n</html>">>,
  {ok, Req2} = cowboy_req:reply(Status, [], Body, Req1),
  {halt, Req2}.

%% @private
%% @doc Convenience function for redirecting to another URL.
-spec reply_redirect(URL, Req) -> {halt, Req} when Req::cowboy_req:req(), URL::binary().
reply_redirect(URL, Req) ->
  {LogURL, Req1} = url(Req),
  lager:debug("Redirecting ~s to ~s", [LogURL, URL]),
  Req2 = cowboy_req:set_resp_header(<<"location">>, URL, Req1),
  {ok, Req3} = cowboy_req:reply(303, Req2),
  {halt, Req3}.

%% @private
%% @doc Return the service URL of this application, which CAS should redirect the client's browser
%% to after login.
-spec login_return_url(Req) -> {URL, Req} when Req::cowboy_req:req(), URL::binary().
login_return_url(Req1) ->
  {Params, Req} = cowboy_req:qs_vals(Req1),
  CleanParams =
    proplists:delete(<<"ticket">>,
    proplists:delete(?GATEWAYED_PARAM,
    proplists:delete(?RETRIES_PARAM,
    proplists:delete(?COOKIE_PARAM,
    Params)))),
  NewParams =
    case core_config(gateway, Req) of
    true -> lists:append(CleanParams, [{?GATEWAYED_PARAM, true}]);
    _ -> CleanParams
    end,
  url(Req, NewParams).

%% @private
%% @doc Return the service URL of this application for use during CAS ticket validation.
-spec ticket_service_url(Req) -> {URL, Req} when Req::cowboy_req:req(), URL::binary().
ticket_service_url(Req1) ->
  {Params, Req} = cowboy_req:qs_vals(Req1),
  CleanParams =
    proplists:delete(<<"ticket">>,
    proplists:delete(?COOKIE_PARAM,
    Params)),
  url(Req, CleanParams).

%% @private
%% @doc Return the service URL of this application with an additional parameter indicating the
%% number of validation attempts that have occurred.
-spec retry_return_url(Req, Attempts) -> {URL, Req}
  when Req::cowboy_req:req(), Attempts::integer(), URL::binary().
retry_return_url(Req1, Retries) ->
  {Params, Req} = cowboy_req:qs_vals(Req1),
  %% GATEWAYED_PARAM shouldn't need to be reset
  CleanParams =
    proplists:delete(<<"ticket">>,
    proplists:delete(?RETRIES_PARAM,
    proplists:delete(?COOKIE_PARAM,
    Params))),
  NewParams = lists:append(CleanParams, [{?RETRIES_PARAM, integer_to_binary(Retries)}]),
  url(Req, NewParams).

%% @private
%% @doc Return the full request URL with an additional query parameter, for testing whether Cookies
%% are enabled in the client's browser.
-spec cookie_test_url(Req) -> {URL, Req} when Req::cowboy_req:req(), URL::binary().
cookie_test_url(Req1) ->
  {Params, Req} = cowboy_req:qs_vals(Req1),
  url(Req, lists:append(Params, [{?COOKIE_PARAM, true}])).

%% @private
%% @doc Return the full request URL with any CAS-related query parameters removed.
-spec clean_url(Req) -> {URL, Req} when Req::cowboy_req:req(), URL::binary().
clean_url(Req1) ->
  {Params, Req} = cowboy_req:qs_vals(Req1),
  NewParams =
    proplists:delete(<<"ticket">>,
    proplists:delete(?GATEWAYED_PARAM,
    proplists:delete(?RETRIES_PARAM,
    proplists:delete(?COOKIE_PARAM,
    Params)))),
  url(Req, NewParams).

%% @private
%% @doc Return the full request URL with any PGT-callback-related query parameters removed.
-spec pgt_url(Req) -> {URL, Req} when Req::cowboy_req:req(), URL::binary().
pgt_url(Req1) ->
  {Params, Req} = cowboy_req:qs_vals(Req1),
  NewParams =
    proplists:delete(<<"pgtIou">>,
    proplists:delete(<<"pgtId">>,
    Params)),
  url(Req, NewParams).

%% @private
%% @doc Return the request URL without the path and query string.  Unlike cowboy_req:host_url(),
%% this uses the X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Port headers if present.
-spec host_url(Req) -> {HostURL, Req} when Req::cowboy_req:req(), HostURL::binary().
host_url(Req1) ->
  {FProto, Req2} = cowboy_req:header(<<"x-forwarded-proto">>, Req1),
  {FHost, Req3} = cowboy_req:header(<<"x-forwarded-host">>, Req2),
  {FPort, Req4} = cowboy_req:header(<<"x-forwarded-port">>, Req3),
  %% Cowboy doesn't currently provide public access to the transport, so we have to use a private
  %% API call to get it
  LProto =
    case (cowboy_req:get(transport, Req4)):name() of
    ssl -> <<"https">>;
    _ -> <<"http">>
    end,
  {LHost, Req5} = cowboy_req:host(Req4),
  {LPort, Req} = cowboy_req:port(Req5),
  Proto =
    case FProto of
    undefined -> LProto;
    _ ->
      [P | _] = re:split(FProto, <<", ?">>, [{return, binary}, {parts, 2}]),
      P
    end,
  Host =
    case FHost of
    undefined -> LHost;
    _ ->
      [H | _] = re:split(FHost, <<", ?">>, [{return, binary}, {parts, 2}]),
      H
    end,
  Port =
    case {FPort, LPort} of
    {undefined, undefined} -> undefined;
    {undefined, _} -> list_to_binary(integer_to_list(LPort));
    _ ->
      [T | _] = re:split(FPort, <<", ?">>, [{return, binary}, {parts, 2}]),
      T
    end,
  UPort =
    case {Proto, Port} of
    {_, undefined} -> <<>>;
    {<<"http">>, <<"80">>} -> <<>>;
    {<<"https">>, <<"443">>} -> <<>>;
    _ -> <<":", Port/binary>>
    end,
  {<< Proto/binary, "://", Host/binary, UPort/binary >>, Req}.

%% @private
%% @doc Return the full request URL.  Unlike cowboy_req:url(), this uses the X-Forwarded-Proto,
%% X-Forwarded-Host, and X-Forwarded-Port headers if present.
-spec url(Req) -> {URL, Req} when Req::cowboy_req:req(), URL::binary().
url(Req1) ->
  {HostURL, Req2} = host_url(Req1),
  {Path, Req3} = cowboy_req:path(Req2),
  {Query, Req} = cowboy_req:qs(Req3),
  URL =
    case Query of
    <<>> -> <<HostURL/binary, Path/binary>>;
    _ -> <<HostURL/binary, Path/binary, "?", Query/binary>>
    end,
  {URL, Req}.

%% @private
%% @doc Return the full request URL, replacing the existing query string with the specified query
%% parameters.  Unlike cowboy_req:url(), this uses the X-Forwarded-Proto, X-Forwarded-Host, and
%% X-Forwarded-Port headers if present.
-spec url(Req, list({Key, Value | true})) -> {URL, Req}
  when Req::cowboy_req:req(), Key::binary(), Value::binary(), URL::binary().
url(Req1, Params) ->
  {HostURL, Req2} = host_url(Req1),
  {Path, Req} = cowboy_req:path(Req2),
  Query =
    case Params of
    [] -> <<>>;
    [H|T] ->
      MergeKV =
        fun
          ({Key, Value}) when Value =:= true -> cas_client_core:url_encode(Key);
          ({Key, Value}) ->
            <<(cas_client_core:url_encode(Key))/binary, "=",
              (cas_client_core:url_encode(Value))/binary>>
        end,
      <<"?", (MergeKV(H))/binary, (<< <<"&", (MergeKV(P))/binary>> || P <- T >>)/binary>>
    end,
  {<<HostURL/binary, Path/binary, Query/binary>>, Req}.
