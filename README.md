# CAS Client for Cowboy

This Erlang OTP application provides [CAS](http://www.jasig.org/cas) Authentication Middleware for the [Cowboy](https://githb.com/extend/cowboy) web server.

All features of the published [CAS protocols](http://www.jasig.org/cas/protocol) are supported, as well as SAML 1.1.

Unfortunately, [Single-Sign-Out](https://wiki.jasig.org/display/CASUM/Single+Sign+Out) cannot be supported because it requires the Middleware to inspect each HTTP request body, but Cowboy only supports reading a request body once.

Canonical source can be found at [https://github.com/PaulSD/erlang_cas_client_cowboy](https://github.com/PaulSD/erlang_cas_client_cowboy)

## Usage

Add this app as a dependency in your rebar.config file:

```erlang
{deps, [
  ...
  {cas_client_cowboy, ".*", {git, "git://github.com/PaulSD/erlang_cas_client_cowboy.git"}}
]}.
```

If applicable, make sure your reltool.config file will include this app and all of its dependencies.

Configure your application to start this app.  For example, in your .app.src file:

```erlang
{application, my_app, [
  ...
  {applications, [
    ...
    cas_client_cowboy
  ]},
  ...
]}.
```

Set configuration options in the cas_client_core, cas_client_cowboy, and giallo_session application environments, typically defined in your app.config file:

```erlang
[
  {cas_client_core, [
    {option_name, option_value},
    ...
  ]},
  {cas_client_cowboy, [ ... ]},
  {giallo_session, [ ... ]}
].
```

Core CAS configuration options (to be set in the cas_client_core app env) are documented in [cas_client_core_config](https://github.com/PaulSD/erlang_cas_client_core/blob/master/src/cas_client_core_config.erl>).  Cowboy-specific CAS configuration options (to be set in the cas_client_cowboy app env) are documented in [cas_client_cowboy_config](blob/master/src/cas_client_cowboy_config.erl).  Cookie and session related options (to be set in the giallo_session app env) are documented in [giallo_session_config](https://github.com/kivra/giallo_session/blob/master/src/giallo_session_config.erl)

Add `cowboy_cas_client` (NOT `cas_client_cowboy`) to the `middlewares` option passed to `cowboy:start_http`:

```erlang
cowboy:start_http(..., [
  {middlewares, [cowboy_cas_client, cowboy_router, cowboy_handler]},
  {env, [{dispatch, Dispatch}]}
]).
```

Optionally use one or more of the following methods in your handler to retrieve CAS-related information:

```erlang
{User, NewReq} = cowboy_cas_client:user(Req)
{Attrs, NewReq} = cowboy_cas_client:attributes(Req)
{AttrValue, NewReq} = cowboy_cas_client:attribute(<<"Attribute Name">>, Req)
{ProxyTicket, NewReq} = cowboy_cas_client:proxy_ticket(ServiceURL, Req)
{CookiesEnabled, NewReq} = cowboy_cas_client:client_cookies_enabled(Req)
```

## Advanced Usage

To request authentication for specific URLs only, or to set CAS configuration options on a URL-specific basis:
* Add `cowboy_filter` instead of `cowboy_cas_client` to the `middlewares` option passed to `cowboy:start_http` (either before or after `cowboy_router`, depending on your needs).
* Configure `cowboy_filter` to call `cowboy_cas_client` for the relevant URLs/handlers.  (See [cowboy_filter](blob/master/src/cowboy_filter.erl) for details.)
* Optionally configure `cowboy_filter` to set CAS configuration options via `cas_client_core` and `cas_client_cowboy` values in the middleware environment.  Any CAS options not specified in the middleware environment will be pulled from the application environment.

For example:

```erlang
Filters =
  cowboy_filter:compile([
    {url, {"cowboy.example.org", [{"/login/[...]", cowboy_cas_client, [
      {cas_client_core, [{gateway, true}]}
    ]}]}},
    {handler, admin_handler, '_', cowboy_cas_client, []}
  ]),
cowboy:start_http(..., [
  {middlewares, [cowboy_router, cowboy_filter, cowboy_handler]},
  {env, [{dispatch, Dispatch}, {filters, Filters}]}
]).
```

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
