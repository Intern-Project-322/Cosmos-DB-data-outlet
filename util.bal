import ballerina/time;
import ballerina/regex;
import ballerina/io;
function getThreeMonthsAgoDate() returns string|error {
    time:Utc currentTime = time:utcNow();
    time:Seconds threeMonths = -7890000;
    time:Utc previoutime = time:utcAddSeconds(currentTime,threeMonths);
    string timeString = time:utcToEmailString(previoutime).trim();
    io:println(timeString);
    string[] splitcomma = regex:split(timeString.trim(),",");
    string[] splitSpace = regex:split(splitcomma[1].trim()," ");
    string timeBefore3Months = string:'join("-",splitSpace[0],splitSpace[1],splitSpace[2]);
    return timeBefore3Months;
};

// public function main() {
//     io:println(getThreeMonthsAgoDate());
// }