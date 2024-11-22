PY = python3
RECS = requirements.txt
OTP = ft_otp.py
VENV = source env/bin/activate

all: install make_exec

venv:
	@echo "Setting up virtual environment..."
	test -d env || $(PY) -m venv env

install: venv
	@echo "Installing python packages..."
	env/bin/pip install --upgrade pip
	. env/bin/activate && pip install -r $(RECS)

make_exec:
	@echo "Making Executables..."
	chmod +x $(OTP)

exit:
	@echo "Removing executable permissions..."
	chmod -x $(OTP)

clean:
	@echo "Cleaning up previous python virtual environment"
	rm -rf env