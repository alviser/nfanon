# nfanon
A simple Netflow anonymizer

This is a really simple tool to anonymize Netflow CSV flows while preserving IPs corrispondence (i.e. different flows that originate from the same IP in the original CSV will still originate from the same anonymized IP after the script has done its job).

## anonymization

IPs are anonymized with the following algorithm:

* anonIP = sha256(IP)

* anonIP is then split into 4 chunks

* each chunk is then converted in int and moduloed 255

* the anonymized address is composed by `chunk1 . chunk2 . chunk3 . chunk4`

***I am not sure this technique is 100% bulletproof***, but should be enough for simple needs.

## usage

`python nfanon.py -i input_netflow.csv [-s salt]`

* the output file will have the same name as the input file prefixed with `anon.`

* the `salt` optional parameter can be used to change the salt from the hardcoded one

