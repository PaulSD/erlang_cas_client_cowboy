%%%-----------------------------------------------------------------------------
%%%
%%% Copyright 2013 Paul Donohue <erlang_cas_client_cowboy@PaulSD.com>
%%%
%%% This file is released under the same license as the Cowboy web server.
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%%-----------------------------------------------------------------------------

%% @doc Cowboy request filter middleware.
%%
%% Execute request filters (cowboy middleware modules) based on the filtering
%% information found in the <em>filters</em> environment value.  If no filters
%% match or if all matching filters return {ok, Req, Env}, then request
%% processing will continue.
%%
%% This may be used, for example, to apply authentication or authorization
%% filters to specific URLs or handlers only.
%%
%% This middleware may be injected either before or after the router middleware,
%% with the caveat that Handler matching will only work if this is injected
%% after the router middleware.
%%
%% The <em>filters</em> environment value should contain the output of
%% <em>cowboy_filter:compile()</em>.  The general structure for the input to
%% <em>cowboy_filter:compile()</em> is:
%% ```
%% Filters = [Match1, Match2, ... ].
%% '''
%%
%% Each Match is either a URL or Handler matching rule that maps to Filter
%% Modules and middleware environment values to use when a match occurs:
%% ```
%% Match1 = {url, {URLMatch}}.
%% Match2 = {handler, Handler, HandlerOpts, Filter, FilterEnv}.
%% '''
%%
%% The URLMatch structure is the same as the Host structure used in Routes,
%% except that the Handler field is used as the Filter, and the Opts field is
%% used as the FilterEnv.
%%
%% In Handler matching rules, the Handler or HandlerOpts value may be '_' to
%% match any Handler or HandlerOpts.
%%
%% FilterEnv is a list of tuples containing names/values to be added to the
%% middleware environment:
%% ```
%% FilterEnv = [{Name1, Value1}, {Name2, Value2}, ... ].
%% '''
%%
%% For example, to authenticate requests to
%% https://cowboy.example.org/login/[...] as well as any requests that are being
%% routed to the admin_handler:
%% ```
%% cowboy_filter:compile([
%%   {url, {"cowboy.example.org", [{"/login/[...]", auth_filter, []}]}},
%%   {handler, admin_handler, '_', auth_filter, []}
%% ])
%% '''
%%
-module(cowboy_filter).
-behaviour(cowboy_middleware).

-export([compile/1]).
-export([execute/2]).

%% Types copied from cowboy_router.erl

-type bindings() :: cowboy_router:bindings().
-type tokens() :: cowboy_router:tokens().
-type constraints() :: cowboy_router:constraints().

-type route_match() :: '_' | iodata().
-type route_path() :: {Path::route_match(), Handler::module(), Opts::any()}
	| {Path::route_match(), constraints(), Handler::module(), Opts::any()}.
-type route_rule() :: {Host::route_match(), Paths::[route_path()]}
	| {Host::route_match(), constraints(), Paths::[route_path()]}.

-type dispatch_match() :: '_' | <<_:8>> | [binary() | '_' | '...' | atom()].
-type dispatch_path() :: {dispatch_match(), module(), any()}.
-type dispatch_rule() :: {Host::dispatch_match(), Paths::[dispatch_path()]}.
-type dispatch_rules() :: [dispatch_rule()].

%% cowboy_filter types

-type handler_match() :: '_' | module().
-type filter_rule() :: {url, route_rule()}
	| {handler, Handler::handler_match(), HandlerOpts::any(),
	   Filter::module(), FilterEnv::any()}.
-type filters() :: [filter_rule()].
-export_type([filters/0]).

-type compiled_filter() :: {url, dispatch_rules()}
	| {handler, Handler::handler_match(), HandlerOpts::any(),
	   Filter::module(), FilterEnv::any()}.
-opaque compiled_filters() :: [compiled_filter()].
-export_type([compiled_filters/0]).



%% @doc Compile a list of filters.
-spec compile(filters()) -> compiled_filters().
compile(Filters) ->
	compile(Filters, []).

compile([], Acc) ->
	Acc;
compile([{url, Route} | Tail], Acc) ->
	compile(Tail, Acc ++ [{url, cowboy_router:compile([Route])}]);
compile([{handler, _, _, _, _} = Head | Tail], Acc) ->
	compile(Tail, Acc ++ [Head]).

%% @private
-spec execute(Req, Env)
	-> {ok, Req, Env}
	| {suspend, module(), atom(), [any()]}
	| {halt, Req}
	| {error, cowboy:http_status(), Req}
	when Req::cowboy_req:req(), Env::cowboy_middleware:env().
execute(Req, Env) ->
	{_, Filters} = lists:keyfind(filters, 1, Env),
	{_, Handler} = lists:keyfind(handler, 1, Env),
	{_, HandlerOpts} = lists:keyfind(handler_opts, 1, Env),
	{Host, Req2} = cowboy_req:host(Req),
	{Path, Req3} = cowboy_req:path(Req2),
	match_filters(Req3, Env, Filters, Handler, HandlerOpts, Host, Path).

match_filters(Req, Env, [], _Handler, _HandlerOpts, _Host, _Path) ->
	{ok, Req, Env};
match_filters(Req, Env, [{url, Routes} | Tail], H, HO, Host, Path) ->
	case match(Routes, Host, Path) of
		{ok, F, FE, _Bindings, _HostInfo, _PathInfo} ->
			run_filter(Req, Env, F, FE, Tail, H, HO, Host, Path);
		{error, badrequest, path} ->
			{error, 400, Req};
		{error, notfound, _} ->
			match_filters(Req, Env, Tail, H, HO, Host, Path)
	end;
match_filters(Req, Env, [{handler, MH, MHO, F, FE} | Tail], H, HO, Host, Path) ->
	case (MH =:= '_' orelse MH =:= H) andalso (MHO =:= '_' orelse MHO =:= HO) of
		true ->
			run_filter(Req, Env, F, FE, Tail, H, HO, Host, Path);
		false ->
			match_filters(Req, Env, Tail, H, HO, Host, Path)
	end.

run_filter(Req, Env, Filter, FilterEnv, Filters, H, HO, Host, Path) ->
	RunEnv = lists:ukeymerge(1, lists:ukeysort(1, FilterEnv), lists:ukeysort(1, Env)),
	try Filter:execute(Req, RunEnv) of
		{ok, Req2, Env2} ->
			match_filters(Req2, Env2, Filters, H, HO, Host, Path);
		Returned -> Returned
	catch Class:Reason ->
		cowboy_req:maybe_reply(500, Req),
		erlang:Class([
			{reason, Reason},
			{mfa, {Filter, execute, 2}},
			{stacktrace, erlang:get_stacktrace()},
			{req, cowboy_req:to_list(Req)},
			{env, Env}
		])
	end.



%%%=============================================================================
%% The below is copied verbatim from cowboy_router.erl

%% @doc Match hostname tokens and path tokens against dispatch rules.
%%
%% It is typically used for matching tokens for the hostname and path of
%% the request against a global dispatch rule for your listener.
%%
%% Dispatch rules are a list of <em>{Hostname, PathRules}</em> tuples, with
%% <em>PathRules</em> being a list of <em>{Path, HandlerMod, HandlerOpts}</em>.
%%
%% <em>Hostname</em> and <em>Path</em> are match rules and can be either the
%% atom <em>'_'</em>, which matches everything, `<<"*">>', which match the
%% wildcard path, or a list of tokens.
%%
%% Each token can be either a binary, the atom <em>'_'</em>,
%% the atom '...' or a named atom. A binary token must match exactly,
%% <em>'_'</em> matches everything for a single token, <em>'...'</em> matches
%% everything for the rest of the tokens and a named atom will bind the
%% corresponding token value and return it.
%%
%% The list of hostname tokens is reversed before matching. For example, if
%% we were to match "www.ninenines.eu", we would first match "eu", then
%% "ninenines", then "www". This means that in the context of hostnames,
%% the <em>'...'</em> atom matches properly the lower levels of the domain
%% as would be expected.
%%
%% When a result is found, this function will return the handler module and
%% options found in the dispatch list, a key-value list of bindings and
%% the tokens that were matched by the <em>'...'</em> atom for both the
%% hostname and path.
-spec match(dispatch_rules(), Host::binary() | tokens(), Path::binary())
	-> {ok, module(), any(), bindings(),
		HostInfo::undefined | tokens(),
		PathInfo::undefined | tokens()}
	| {error, notfound, host} | {error, notfound, path}
	| {error, badrequest, path}.
match([], _, _) ->
	{error, notfound, host};
%% If the host is '_' then there can be no constraints.
match([{'_', [], PathMatchs}|_Tail], _, Path) ->
	match_path(PathMatchs, undefined, Path, []);
match([{HostMatch, Constraints, PathMatchs}|Tail], Tokens, Path)
		when is_list(Tokens) ->
	case list_match(Tokens, HostMatch, []) of
		false ->
			match(Tail, Tokens, Path);
		{true, Bindings, HostInfo} ->
			HostInfo2 = case HostInfo of
				undefined -> undefined;
				_ -> lists:reverse(HostInfo)
			end,
			case check_constraints(Constraints, Bindings) of
				{ok, Bindings2} ->
					match_path(PathMatchs, HostInfo2, Path, Bindings2);
				nomatch ->
					match(Tail, Tokens, Path)
			end
	end;
match(Dispatch, Host, Path) ->
	match(Dispatch, split_host(Host), Path).

-spec match_path([dispatch_path()],
	HostInfo::undefined | tokens(), binary() | tokens(), bindings())
	-> {ok, module(), any(), bindings(),
		HostInfo::undefined | tokens(),
		PathInfo::undefined | tokens()}
	| {error, notfound, path} | {error, badrequest, path}.
match_path([], _, _, _) ->
	{error, notfound, path};
%% If the path is '_' then there can be no constraints.
match_path([{'_', [], Handler, Opts}|_Tail], HostInfo, _, Bindings) ->
	{ok, Handler, Opts, Bindings, HostInfo, undefined};
match_path([{<<"*">>, _Constraints, Handler, Opts}|_Tail], HostInfo, <<"*">>, Bindings) ->
	{ok, Handler, Opts, Bindings, HostInfo, undefined};
match_path([{PathMatch, Constraints, Handler, Opts}|Tail], HostInfo, Tokens,
		Bindings) when is_list(Tokens) ->
	case list_match(Tokens, PathMatch, Bindings) of
		false ->
			match_path(Tail, HostInfo, Tokens, Bindings);
		{true, PathBinds, PathInfo} ->
			case check_constraints(Constraints, PathBinds) of
				{ok, PathBinds2} ->
					{ok, Handler, Opts, PathBinds2, HostInfo, PathInfo};
				nomatch ->
					match_path(Tail, HostInfo, Tokens, Bindings)
			end
	end;
match_path(_Dispatch, _HostInfo, badrequest, _Bindings) ->
	{error, badrequest, path};
match_path(Dispatch, HostInfo, Path, Bindings) ->
	match_path(Dispatch, HostInfo, split_path(Path), Bindings).

check_constraints([], Bindings) ->
	{ok, Bindings};
check_constraints([Constraint|Tail], Bindings) ->
	Name = element(1, Constraint),
	case lists:keyfind(Name, 1, Bindings) of
		false ->
			check_constraints(Tail, Bindings);
		{_, Value} ->
			case check_constraint(Constraint, Value) of
				true ->
					check_constraints(Tail, Bindings);
				{true, Value2} ->
					Bindings2 = lists:keyreplace(Name, 1, Bindings,
						{Name, Value2}),
					check_constraints(Tail, Bindings2);
				false ->
					nomatch
			end
	end.

check_constraint({_, int}, Value) ->
	try {true, list_to_integer(binary_to_list(Value))}
	catch _:_ -> false
	end;
check_constraint({_, function, Fun}, Value) ->
	Fun(Value).

%% @doc Split a hostname into a list of tokens.
-spec split_host(binary()) -> tokens().
split_host(Host) ->
	split_host(Host, []).

split_host(Host, Acc) ->
	case binary:match(Host, <<".">>) of
		nomatch when Host =:= <<>> ->
			Acc;
		nomatch ->
			[Host|Acc];
		{Pos, _} ->
			<< Segment:Pos/binary, _:8, Rest/bits >> = Host,
			false = byte_size(Segment) == 0,
			split_host(Rest, [Segment|Acc])
	end.

%% @doc Split a path into a list of path segments.
%%
%% Following RFC2396, this function may return path segments containing any
%% character, including <em>/</em> if, and only if, a <em>/</em> was escaped
%% and part of a path segment.
-spec split_path(binary()) -> tokens().
split_path(<< $/, Path/bits >>) ->
	split_path(Path, []);
split_path(_) ->
	badrequest.

split_path(Path, Acc) ->
	try
		case binary:match(Path, <<"/">>) of
			nomatch when Path =:= <<>> ->
				lists:reverse([cowboy_http:urldecode(S) || S <- Acc]);
			nomatch ->
				lists:reverse([cowboy_http:urldecode(S) || S <- [Path|Acc]]);
			{Pos, _} ->
				<< Segment:Pos/binary, _:8, Rest/bits >> = Path,
				split_path(Rest, [Segment|Acc])
		end
	catch
		error:badarg ->
			badrequest
	end.

-spec list_match(tokens(), dispatch_match(), bindings())
	-> {true, bindings(), undefined | tokens()} | false.
%% Atom '...' matches any trailing path, stop right now.
list_match(List, ['...'], Binds) ->
	{true, Binds, List};
%% Atom '_' matches anything, continue.
list_match([_E|Tail], ['_'|TailMatch], Binds) ->
	list_match(Tail, TailMatch, Binds);
%% Both values match, continue.
list_match([E|Tail], [E|TailMatch], Binds) ->
	list_match(Tail, TailMatch, Binds);
%% Bind E to the variable name V and continue,
%% unless V was already defined and E isn't identical to the previous value.
list_match([E|Tail], [V|TailMatch], Binds) when is_atom(V) ->
	case lists:keyfind(V, 1, Binds) of
		{_, E} ->
			list_match(Tail, TailMatch, Binds);
		{_, _} ->
			false;
		false ->
			list_match(Tail, TailMatch, [{V, E}|Binds])
	end;
%% Match complete.
list_match([], [], Binds) ->
	{true, Binds, undefined};
%% Values don't match, stop.
list_match(_List, _Match, _Binds) ->
	false.
