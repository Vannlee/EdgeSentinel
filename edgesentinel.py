import argparse
from argparse import RawTextHelpFormatter
# import os
# import sys
# import re

def quick_scan(url):
    "function will scan for first 12 CWEs of A10"
    try:
        print(f"Conducting scanning for the first 12 CWEs for {url}")

    except:
        print("Use '-h' for more information on the usage of EdgeSentinel")


def specify_scan(url, scan_cwe):
    "function will scan for specified CWEs"
    try:
        cwes = {1 : "CWE-209 Generation of Error Message Containing "
                "Sensitive Information", 2 : "CWE-215 Insertion of Sensitive "
                "Information Into Debugging Code", 3 : "CWE-234 Failure to "
                "Handle Missing Parameter", 4 : "CWE-235 Improper Handling of "
                "Extra Parameters", 5 : "CWE-248 Uncaught Exception", 
                6 : "CWE-252 Unchecked Return Value", 7 : "CWE-274 Improper "
                "Handling of Insufficient Privileges", 8 : "CWE-280 Improper "
                "Handling of Insufficient Permissions or Privileges", 
                9 : "CWE-369 Divide By Zero", 10 : "CWE-390 Detection of "
                "Error Condition Without Action", 11 : "CWE-391 Unchecked "
                "Error Condition", 12 : "CWE-394 Unexpected Status Code or "
                "Return Value", 13 : "CWE-396 Declaration of Catch for "
                "Generic Exception", 14 : "CWE-397 Declaration of Throws for "
                "Generic Exception", 15 : "CWE-460 Improper Cleanup on Thrown "
                "Exception", 16 : "CWE-476 NULL Pointer Dereference", 
                17 : "CWE-478 Missing Default Case in Multiple Condition "
                "Expression", 18 : "CWE-484 Omitted Break Statement in Switch",
                19 : "CWE-550 Server-generated Error Message Containing "
                "Sensitive Information", 20 : "CWE-636 Not Failing Securely "
                "('Failing Open')", 21 : "CWE-703 Improper Check or Handling "
                "of Exceptional Conditions", 22 : "CWE-754 Improper Check for "
                "Unusual or Exceptional Conditions", 23 : "CWE-755 Improper "
                "Handling of Exceptional Conditions", 24 : "CWE-756 Missing "
                "Custom Error Page"}
        scan_cwe = [int(number) for number in scan_cwe]

        print("Conducting scanning for the chosen CWES:\n")
        for number in scan_cwe:
            print(f"{number}. {cwes[number]}")

    except ValueError:
        print("CWEs specified can only be integers from 1-24")


def default_scan(url):
    "function will scan for all 24 CWEs under A10"
    try:
        print(f"Conducting scanning for all 24 CWEs for {url}")

    except:
        print("Use '-h' for more information on the usage of EdgeSentinel")



def main():
    parser = argparse.ArgumentParser(description="EdgeSentinel is a command "
                                     "line focused detection tool that helps "
                                     "testers and developers identify OWASP "
                                     "A10 relevant weaknesses from a target "
                                     "URL", formatter_class=RawTextHelpFormatter)
    parser.add_argument("url", help="Target URL to be analysed for all 24 "
                        "CWEs under A10 by default unless the '-q' or '-s' "
                        "flag is specified")
    parser_args = parser.add_mutually_exclusive_group(required=False) 
    parser_args.add_argument("-q", "--quick_scan", action="store_true", 
                             help="Used to specify a quick analysis, "
                                "checking for the first 12 CWEs under A10 "
                                "instead of doing a complete analysis for all "
                                "24 CWEs")
    parser_args.add_argument("-s", "--specify",
                             help="Used to specify the CWEs to be tested "
                                "for, using numbers separated by commas."
                                "\nThe list of CWEs are as follows:\n1. "
                                "CWE-209 Generation of Error Message "
                                "Containing Sensitive Information\n2. CWE-215 "
                                "Insertion of Sensitive Information Into "
                                "Debugging Code\n3. CWE-234 Failure to Handle "
                                "Missing Parameter\n4. CWE-235 Improper "
                                "Handling of Extra Parameters\n5. CWE-248 "
                                "Uncaught Exception\n6. CWE-252 Unchecked "
                                "Return Value\n7. CWE-274 Improper Handling "
                                "of Insufficient Privileges\n8. CWE-280 "
                                "Improper Handling of Insufficient "
                                "Permissions or Privileges\n9. CWE-369 Divide "
                                "By Zero\n10. CWE-390 Detection of Error "
                                "Condition Without Action\n11. CWE-391 "
                                "Unchecked Error Condition\n12. CWE-394 "
                                "Unexpected Status Code or Return Value\n13. "
                                "CWE-396 Declaration of Catch for Generic "
                                "Exception\n14. CWE-397 Declaration of Throws "
                                "for Generic Exception\n15. CWE-460 Improper "
                                "Cleanup on Thrown Exception\n16. CWE-476 "
                                "NULL Pointer Dereference\n17. CWE-478 "
                                "Missing Default Case in Multiple Condition "
                                "Expression\n18. CWE-484 Omitted Break "
                                "Statement in Switch\n19. CWE-550 "
                                "Server-generated Error Message Containing "
                                "Sensitive Information\n20. CWE-636 Not "
                                "Failing Securely ('Failing Open')\n21. "
                                "CWE-703 Improper Check or Handling of "
                                "Exceptional Conditions\n22. CWE-754 Improper "
                                "Check for Unusual or Exceptional Conditions\n"
                                "23. CWE-755 Improper Handling of Exceptional "
                                "Conditions\n24. CWE-756 Missing Custom "
                                "Error Page")
            
    arguments = parser.parse_args()
    url = arguments.url

    if (arguments.quick_scan):
        quick_scan(url)
    elif (arguments.specify):
        scan_cwe = (arguments.specify).split(",")
        specify_scan(url, scan_cwe)
    else:
        default_scan(url)


if __name__=='__main__':
    main()
