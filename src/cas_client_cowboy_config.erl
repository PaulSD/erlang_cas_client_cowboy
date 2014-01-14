%%%-------------------------------------------------------------------------------------------------
%%%
%%% Copyright 2013 Paul Donohue <erlang_cas_client_cowboy@PaulSD.com>
%%%
%%% This program is free software: you can redistribute it and/or modify
%%% it under the terms of the GNU General Public License as published by
%%% the Free Software Foundation, either version 3 of the License, or
%%% (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%% GNU General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program.  If not, see {http://www.gnu.org/licenses/}.
%%%
%%%-------------------------------------------------------------------------------------------------

%% @doc Cowboy-specific CAS Client Configuration, read from the 'cas_client_cowboy' application
%% environment.
%%
%% Options:
%% logout_path			(Default is <<"/logout">>)
%%   The application URL path (as a binary string) at which the CAS client should accept logout
%%   requests, or 'undefined' to disable the logout interface.
%%
-module(cas_client_cowboy_config).

-export([get/1, get_default/1, validate/2, validate/1]).

%% @doc Read the specified configuration value (or its documented default) from the
%% 'cas_client_cowboy' application environment.  Returns 'undefined' if the value does not exist and
%% does not have a documented default value.
-spec get(Key) -> Value when Key::atom(), Value::any().
get(Key) ->
  case application:get_env(cas_client_cowboy, Key) of
  undefined -> get_default(Key);
  {ok, Value} -> Value
  end.

%% @doc Return the documented default value for the specified configuration key.  Returns
%% 'undefined' if the specified configuration key does not have a documented default value.
-spec get_default(Key) -> Value when Key::atom(), Value::any().
get_default(Key) ->
  case Key of
  logout_path -> <<"/logout">>;
  _ -> undefined
  end.

%% @doc Validate the data type of the specified option.
-spec validate(Key, Value) -> ok | {error, Message}
  when Key::atom(), Value::any(), Message::string().
validate(Key, Value) ->
  CheckFun =
    case Key of
    logout_path -> fun(X) when X =:= undefined orelse is_binary(X) -> X end;
    _ -> fun(X) -> X end
    end,
  case catch CheckFun(Value) of
  {'EXIT', _} ->
    {error, io_lib:format("cas_client_cowboy configuration problem: Invalid ~s: ~p", [Key, Value])};
  _ -> ok
  end.

%% @doc Validate presence of required options and data types of all options.
-spec validate(cas_client_core:config_get_fun()) -> ok | {error, Message} when Message::string().
validate(ConfigFun) ->
  Options = [logout_path],
  lists:foldl(
    fun
    (O, ok) ->
      Value =
        case ConfigFun of
        undefined -> cas_client_cowboy_config:get(O);
        _ -> ConfigFun(O)
        end,
      validate(O, Value);
    (_O, A) -> A
    end,
  ok, Options).
