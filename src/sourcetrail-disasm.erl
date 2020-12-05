%#!/usr/bin/env escript
%% -*- erlang -*-
-module('sourcetrail-disasm').

-export([main/1]).
-define(FAIL, erlang:halt(1)).

main([]) ->
  io:format("Usage: sourcetrail-disasm file.beam~n", []);
main([Path]) ->
  {ok, Beam} = file:read_file(Path),
  FormTree = try_get_abstract_code(Path, Beam),
  J = scan_form(FormTree),
  Json = jsx:encode(#{forms => J}),
  io:format("~s~n", [Json]).


try_get_abstract_code(Path, Beam) ->
  case beam_lib:chunks(Beam, [abstract_code]) of
    {ok, {_Module, [{abstract_code, {_, AC}}]}} ->
      erl_syntax:form_list(AC);
    {ok, {_Module, [{abstract_code, no_abstract_code}]}} ->
      io:format(standard_error, "ERROR: no abstract code for ~p (use +debug_info for erlc)~n", [Path]),
      ?FAIL
  end.


%%try_get_code(Beam) ->
%%  {ok, {disasm, [{"Code", C}]}} = beam_lib:chunks(Beam, ["Code"]),
%%  <<_CodeVer:32/big, _MinOpcode:32/big, _MaxOpcode:32/big, _NumLabels:32/big, _NumFuns:32/big, Code/binary>> = C,
%%  io:format("~w~n", [Code]).


%% @doc First level scan (attributes and functions)
scan_form({tree, form_list, _Attr, L}) -> scan_form_list(L);

scan_form({attribute, Line, Name, Value}) ->
  #{
    type => <<"attr">>,
    name => Name,
    line => Line
    % value => scan_expr(Value) % attrs can be raw atoms, strings and any unstructured form trees
  };

scan_form({function, Line, Name, Arity, Code}) ->
  #{
    type => <<"function">>,
    name => Name,
    arity => Arity,
    line => Line,
    code => scan_expr_list(Code)
  };

scan_form({eof, Line}) -> #{type => <<"eof">>, line => Line};

scan_form(Element) ->
  erlang:error({error, "FORM not handled", Element}).


%% @doc Scan elements of code and expressions
scan_expr({clause, _Line, Expr, GuardList, Code}) ->
  #{
    type => <<"clause">>,
    expr => scan_expr_list(Expr),
    guard => lists:map(fun(Guard) -> scan_expr_list(Guard) end, GuardList),
    code => scan_expr_list(Code)
  };

scan_expr({'case', _Line, Expr, Code}) ->
  #{
    type => <<"case">>,
    expr => scan_expr(Expr),
    code => scan_expr_list(Code)
  };

scan_expr({call, _Line, Target, Args}) ->
  #{
    type => <<"call">>,
    target => scan_expr(Target),
    args => scan_expr_list(Args)
  };

scan_expr({var, Line, Name}) ->
  #{
    type => <<"var">>,
    line => Line,
    name => Name
  };

scan_expr({'fun', Line, {clauses, Clauses}}) ->
  #{
    type => <<"fun">>,
    line => Line,
    clauses => scan_expr_list(Clauses)
  };

scan_expr({'atom', Line, A}) ->
  #{
    type => <<"atom">>,
    line => Line,
    name => erlang:atom_to_binary(A, utf8)
  };

scan_expr({'tuple', Line, Elements}) ->
  #{
    type => <<"tuple">>,
    line => Line,
    elements => scan_expr_list(Elements)
  };

scan_expr({'cons', Line, H, T}) ->
  #{
    type => <<"cons">>,
    line => Line,
    head => scan_expr(H),
    tail => scan_expr(T)
  };

scan_expr({'remote', Line, Module, Function}) ->
  #{
    type => <<"remote">>,
    line => Line,
    mod => scan_expr(Module),
    'fun' => scan_expr(Function)
  };

scan_expr({'match', Line, Var, Value}) ->
  #{
    type => <<"match">>,
    line => Line,
    var => scan_expr(Var),
    value => scan_expr(Value)
  };

scan_expr({'record', Line, Name, Fields}) ->
  #{
    type => <<"record">>,
    line => Line,
    rec_name => Name,
    fields => scan_expr_list(Fields)
  };

scan_expr({'record', Line, VarName, RecName, Fields}) ->
  #{
    type => <<"record">>,
    line => Line,
    var_name => scan_expr(VarName),
    rec_name => RecName,
    fields => scan_expr_list(Fields)
  };

scan_expr({'record_field', Line, Name, Value}) ->
  #{
    type => <<"record_field">>,
    line => Line,
    rec_name => scan_expr(Name),
    value => scan_expr(Value)
  };

scan_expr({'record_field', Line, VarName, RecName, FieldName}) ->
  #{
    type => <<"record_field">>,
    line => Line,
    var => scan_expr(VarName),
    rec_name => RecName,
    field_name => scan_expr(FieldName)
  };

scan_expr({'bin', Line, Components}) ->
  #{
    type => <<"binary">>,
    line => Line,
    components => scan_expr_list(Components)
  };

scan_expr({'bin_element', Line, Var, _Mode, _Flags}) ->
  #{
    type => <<"binary_element">>,
    line => Line,
    var => scan_expr(Var)
  };

scan_expr({'op', Line, Op, A, B}) ->
  #{
    type => <<"op">>,
    line => Line,
    op => erlang:atom_to_binary(Op, utf8),
    a => scan_expr(A),
    b => scan_expr(B)
  };

scan_expr({'try', Line, Expr, A, B, C}) ->
  #{
    type => <<"try">>,
    line => Line,
    expr => scan_expr_list(Expr),
    a => scan_expr_list(A),
    b => scan_expr_list(B),
    c => scan_expr_list(C)
  };

scan_expr({nil, _Line}) -> #{type => <<"nil">>};
scan_expr({integer, _Line, N}) -> #{type => <<"int">>, value => N};
scan_expr({char, _Line, N}) -> #{type => <<"char">>, value => N};
scan_expr({string, _Line, S}) ->
  #{
    type => <<"str">>,
    value => unicode:characters_to_binary(S)
  };

%%scan_expr(Atom) when is_atom(Atom) ->
%%  #{
%%    type => <<"atom">>,
%%    value => erlang:atom_to_binary(Atom, utf8)
%%  };

scan_expr(Element) ->
  erlang:error({error, "EXPR not handled", Element}).


scan_expr_list(ExprList) ->
  lists:map(fun(C) -> scan_expr(C) end, ExprList).

scan_form_list(FList) ->
  lists:map(fun(C) -> scan_form(C) end, FList).
