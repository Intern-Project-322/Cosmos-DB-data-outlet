import ballerina/time;
import ballerina/regex;
import ballerina/io;
function getThreeMonthsAgoDate() returns string|error {
    time:Utc currentTime = time:utcNow();
    time:Seconds threeMonths = -7890000;
    time:Utc previoutime = time:utcAddSeconds(currentTime,threeMonths);
    time:Civil civil = time:utcToCivil(previoutime);
    io:println(civil);
    io:println("");
    string timeString = time:utcToEmailString(previoutime).trim();
    //io:println(timeString);
    string[] splitcomma = regex:split(timeString.trim(),",");
    string[] splitSpace = regex:split(splitcomma[1].trim()," ");
    string timeBefore3Months = string:'join("-",splitSpace[0],splitSpace[1],splitSpace[2]);
    


    // time:Utc utc = time:utcNow();
    // time:Civil civil = time:utcToCivil(utc);
    // string created_time = civil.hour.toString() + ":" + civil.minute.toString() + ":" + (<int>civil.second).toString();
    // string created_date = civil.year.toString()+"-"+civil.month.toString() + "-" + civil.day.toString();
    // io:println(created_time);
    // io:println(created_date);
    return timeBefore3Months;
};

// public function main() {
//     io:println(getThreeMonthsAgoDate());
// }