#!/bin/bash

COLUMNS=101                          # Used for center text
FAILURES=0                           # Number of test failures
SUCCESSES=0                          # Numer of test successes
TOTAL_MEM_ERRORS=0                   # Errors detected with memcheck
TOTAL_HELGRIND_ERRORS=0              # Errors detected with helgrind tool
TOTAL_DRD_ERRORS=0                   # Errors detected with drd

# Count number of XML elements that match with string $2 in file $1
function count_xml_elms {
  xml-find $1 -name $2 | wc -l
}

# Extract valgrind error text $2 of file $1
function valgrind_xml_error_text {
  TEXT="$(xml-printf '%s' $1 ://error[$2]/what 2>/dev/null)"
  if [[ -z "$TEXT" ]]; then
    TEXT="$(xml-printf '%s' $1 ://error[$2]/xwhat/text 2>/dev/null)"
  fi
  echo "$TEXT"
}

TITLE="TESTS RESULTS"
printf "\n\e[1m\e[34m%*s\e[0m\n" $(((${#TITLE}+$COLUMNS)/2)) "$TITLE"
printf "\e[1m\e[34m=====================================================================================================\e[0m\n"
printf "\n"

while getopts "cvhd" opt; do
  case $opt in
    c) DO_CHECKS="y";;
    v) DO_VALGRIND="y";;
    h) DO_HELGRIND="y";;
    d) DO_DRD="y";;
    \?) echo "Invalid option: -$OPTARG" >&2;;
  esac
done
shift $((OPTIND -1))

# Check for every .test file
for FILE in $*; do
  # Saved results on XML files
  RESULT_XML="$FILE".xml
  MEM_XML="$FILE".mem.xml
  HELGRIND_XML="$FILE".helgrind.xml
  DRD_XML="$FILE".drd.xml

  TESTCASES=0
  # Count errors
  MEM_ERRORS=0                        # Errors detected with memcheck tool
  HELGRIND_ERRORS=0                   # Errors detected with helgrind tool
  DRD_ERRORS=0                        # Errors detected with drd

  printf "\e[1m=====================================================================================================\e[0m\n"
  printf "\e[1m%*s\e[0m\n" $(((${#FILE}+$COLUMNS)/2)) "$FILE"
  printf "\e[1m=====================================================================================================\e[0m\n"

  # Get previous information
  if [[ "x$DO_CHECKS" == "xy" ]]; then
    TESTCASES=$(count_xml_elms "$RESULT_XML" "testcase")
  fi
  if [[ "x$DO_VALGRIND" == "xy" ]]; then
    MEM_ERRORS="$(count_xml_elms $MEM_XML error)"
  fi
  if [[ "x$DO_HELGRIND" == "xy" ]]; then
    HELGRIND_ERRORS="$(count_xml_elms $HELGRIND_XML error)"
  fi
  if [[ "x$DO_DRD" == "xy" ]]; then
    DRD_ERRORS="$(count_xml_elms $DRD_XML error)"
  fi

  # Check the tests results
  for i in $(seq 1 $TESTCASES); do
    # Parse the XML
    TIME=$(xml-printf '%s' $RESULT_XML ://testcase[$i]@time)
    NAME=$(xml-printf '%s' $RESULT_XML ://testcase[$i]@name)
    FAIL=$(xml-printf '%s' $RESULT_XML ://testcase[$i])
    xml-printf '%s' $RESULT_XML ://testcase[$i]/skipped >/dev/null 2>&1
    SKIPPED=$?

    if [ "$SKIPPED" -eq 0 ]; then
      # Skipped tests
      printf "\t\e[90m ○ %s \e[0m(Skipped)\e[0m\n" "$NAME"
    elif [ -z "$FAIL" ] && [ $MEM_ERRORS -eq 0 ] && [ $HELGRIND_ERRORS -eq 0 ] && [ $DRD_ERRORS -eq 0 ]; then
      # No errors at all
      printf "\t\e[32m ✔ %s \e[0m(%sms)\e[0m\n" "$NAME" "$TIME"
      ((SUCCESSES++))
    elif [ -z "$FAIL" ]; then
      # Tests are ok but valgrind found some issues
      printf "\t\e[33m ✔ %s \e[0m(%sms)\e[0m\n" "$NAME" "$TIME"
      ((SUCCESSES++))
    else
      # Errors found in tests
      printf "\t\e[1m\e[31m ✘ %s\e[0m\n" "$NAME"
      printf "\t\t\e[31m• %s\e[0m\n" "$FAIL"
      ((FAILURES++))
    fi
  done

  # Check the valgrind memcheck results
  if [[ $MEM_ERRORS -gt 0 ]] ; then
    printf '\n'
    printf "\t\e[1m---------------------------------------------------------------------------------------------\e[0m\n"
    printf "\t\e[1m Memory issues\n"
    printf "\t\e[1m---------------------------------------------------------------------------------------------\e[0m\n"

    LOST=0 # Count memory lost due to memory leaks
    for i in $(seq 1 $MEM_ERRORS); do
      # Display error
      TEXT="$(valgrind_xml_error_text $MEM_XML $i)"
      printf "\t\e[33m • %s\e[0m\n" "$TEXT"

      # Count bytes lost due to this error
      BYTES="$(xml-printf '%s' $MEM_XML ://error[$i]/xwhat/leakedbytes 2>/dev/null)"
      ((LOST+=BYTES))
    done

    printf "\n"
    printf "\t TOTAL MEMORY LEAKED: %s BYTES\e[0m\n" "$LOST"
    printf "\t\e[1m---------------------------------------------------------------------------------------------\e[0m\n"
  fi

  # Check the valgrind drd and helgrind tools results
  if [[ $HELGRIND_ERRORS -gt 0 ]] || [[ $DRD_ERRORS -gt 0 ]]; then
    printf '\n'
    printf "\t\e[1m---------------------------------------------------------------------------------------------\e[0m\n"
    printf "\t\e[1m Concurrency issues\n"
    printf "\t\e[1m---------------------------------------------------------------------------------------------\e[0m\n"

    for i in $(seq 1 $HELGRIND_ERRORS); do
      # Display helgrind error
      TEXT="$(valgrind_xml_error_text $HELGRIND_XML $i)"
      printf "\t\e[33m • \e[1m[HELGRIND] \e[0;33m%s\e[0m\n" "$TEXT"
    done

    for i in $(seq 1 $DRD_ERRORS); do
      # Display drd error
      TEXT="$(valgrind_xml_error_text $DRD_XML $i)"
      printf "\t\e[33m • \e[1m[DRD] \e[0;33m%s\e[0m\n" "$TEXT"
    done
    printf "\t\e[1m---------------------------------------------------------------------------------------------\e[0m\n"
  fi

  TOTAL_MEM_ERRORS=$((TOTAL_MEM_ERRORS + MEM_ERRORS))
  TOTAL_HELGRIND_ERRORS=$((TOTAL_HELGRIND_ERRORS + HELGRIND_ERRORS))
  TOTAL_DRD_ERRORS=$((TOTAL_DRD_ERRORS + DRD_ERRORS))

  printf "\n"
done

# Show a digest of all errors
CONCURRENCY_ERRORS=$((TOTAL_HELGRIND_ERRORS + TOTAL_DRD_ERRORS))
TOTAL_ERRORS=$((FAILURES + TOTAL_MEM_ERRORS + CONCURRENCY_ERRORS))

if [ $FAILURES -gt 0 ]; then
  COLOR="\e[1m\e[31m"
  TITLE="NOT PASSED"
elif [ $TOTAL_ERRORS -gt 0 ]; then
  COLOR="\e[1m\e[33m"
  TITLE="NOT PASSED"
else
  COLOR="\e[1m\e[32m"
  TITLE="PASSED"
fi

RESULT=$(printf "SUCESSES: %s | FAILURES: %s | MEMORY: %s | CONCURRENCY: %s\e[0m\n" "$SUCCESSES" "$FAILURES" "$TOTAL_MEM_ERRORS" "$CONCURRENCY_ERRORS")
echo -e "$COLOR=====================================================================================================\e[0m"
printf "$COLOR%*s\e[0m\n" $(((${#TITLE}+$COLUMNS)/2)) "$TITLE"
printf "\n"
printf "$COLOR%*s\e[0m\n" $(((${#RESULT}+$COLUMNS)/2)) "$RESULT"
echo -e "$COLOR=====================================================================================================\e[0m"
printf "\n"

if [ $((FAILURES + TOTAL_ERRORS)) -gt 0 ]; then
  exit 1
fi
