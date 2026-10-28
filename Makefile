.PHONY: test

test:
	PYTHONPATH="common:detection:integrations/nftables:data-plane:control-plane:integrations/providers" python3 -m unittest discover -s tests -v
