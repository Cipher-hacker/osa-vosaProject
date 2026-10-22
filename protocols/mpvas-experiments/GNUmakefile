export APT_PKGS = curl git wget build-essential bison flex libffi-dev libgmp-dev libssl-dev zlib1g-dev
export PYENV_ROOT := $(HOME)/.pyenv
export PATH := $(PYENV_ROOT)/bin:$(PATH)

export PYENV_INIT = if command -v pyenv >/dev/null 2>&1; then eval "$(pyenv init -)" && eval "$(pyenv virtualenv-init -)"; fi
export PYENV_ACTIVATE = if command -v pyenv >/dev/null 2>&1; then eval "$(pyenv init -)" && eval "$(pyenv virtualenv-init -)" && ( [ -n "$VIRTUAL_ENV" ] && pyenv activate --unset || true ) && eval "$(pyenv init -)" && eval "$(pyenv virtualenv-init -)" && pyenv activate mpvas-env; fi

.PHONY: install
install: install/apt install/pyenv install/charm install/mpvas

.PHONY: install/contrib
install/contrib: install install/mpvas/contrib

.PHONY: install/apt
install/apt:
	# Installing dependencies through apt
	@sudo apt update
	@sudo apt -y install $(APT_PKGS)

.PHONY: install/pyenv
install/pyenv:
	# Install and configure pyenv
	@curl https://pyenv.run | bash
	@eval "$(pyenv init -)" && pyenv install 3.8.18 && pyenv global 3.8.18
	@eval "$(pyenv init -)" && eval "$(pyenv virtualenv-init -)" && pyenv virtualenv mpvas-env

.PHONY: install/charm
install/charm:
	# Install Charm
	@git clone https://github.com/JHUISI/charm

	# Configure Charm
	@cd charm; git checkout 2b58a7ebf758c7c4ce81be0378989cccf1fd39ad
	@cd charm; $(PYENV_ACTIVATE); ./configure.sh

	# Install Charm -> pbc
	@cd charm/deps/pbc; $(PYENV_ACTIVATE); make
	@sudo ldconfig

	# Install Charm
	@cd charm; $(PYENV_ACTIVATE); make
	@cd charm; $(PYENV_ACTIVATE); make install
	@rm -rf charm

.PHONY: install/mpvas
install/mpvas:
	# Install Python dependencies
	@$(PYENV_ACTIVATE); pip install .

.PHONY: install/mpvas/contrib
install/mpvas/contrib:
	# Install Python contributor dependencies
	@$(PYENV_ACTIVATE); pip install .[contribute]

.PHONY: uninstall
uninstall: uninstall/pbc uninstall/pyenv uninstall/apt

.PHONY: uninstall/charm
uninstall/pbc:
	# Removing pbc
	@sudo rm -rf /usr/include/pbc/
	@sudo rm -rf /usr/lib/libpbc.a /usr/lib/libpbc.la /usr/lib/libpbc.so /usr/lib/libpbc.so.1 /usr/lib/libpbc.so.1.0.0
	@sudo ldconfig

.PHONY: uninstall/pyenv
uninstall/pyenv:
	# Removing pyenv
	@rm -rf "$$PYENV_ROOT"

.PHONY: uninstall/apt
uninstall/apt:
	# Removing apt packages
	@echo "Cannot automatically uninstall packages, because that would be really dangerous. To uninstall the packages installed for the mPVAS experiments, run the following command, and very carefully inspect the output to see if it makes sense:\n\n  sudo apt remove $(APT_PKGS)"


.PHONY: test
test:
	@$(PYENV_ACTIVATE); src/testrun/test.sh

.PHONY: run
run:
	@$(PYENV_ACTIVATE); src/testrun/run.sh

.PHONY: plot
plot:
	@cd src; $(PYENV_ACTIVATE); ${PYTHON_BIN:-python3} -m testrun.plot


.PHONY: clean
clean:
	@rm -rf out


.PHONY: black
black:
	@$(PYENV_ACTIVATE); black src

.PHONY: mypy
mypy:
	@$(PYENV_ACTIVATE); mypy src
