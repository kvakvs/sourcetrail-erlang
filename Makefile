.PHONY: cmake compile run

run: compile
	_build/default/bin/sourcetrail-disasm _build/default/lib/jsx/ebin/jsx_to_term.beam

cmake:
	rm -rf build_ && mkdir build_ && cd build_ && \
	BUILD_EXAMPLES=ON BUILD_BINDINGS_PYTHON=ON cmake ..

compile:
	rebar3 escriptize
