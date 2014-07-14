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

%% @doc Application Manager for the CAS Client for Cowboy
-module(cas_client_cowboy).

-export([start/0]).
-behaviour(application).
-export([start/2, stop/1]).



start() ->
  ok = application:start(cas_client_cowboy).

start(_Type, _Args) ->
  case cas_client_cowboy_config:validate(undefined) of
  {error, Message} ->
    lager:error("~s", [Message]),
    throw({error, Message});
  _ -> ok
  end,
  {ok, self()}.

stop(_Args) ->
  ok.
