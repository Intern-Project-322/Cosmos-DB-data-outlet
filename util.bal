import ballerina/time;
import ballerina/regex;
//import ballerina/log;
import ballerina/io;
function getThreeMonthsAgoDate() returns time:Utc {
    time:Utc currentTime = time:utcNow();
    time:Seconds threeMonths = -7890000;
    time:Utc previoutime = time:utcAddSeconds(currentTime,threeMonths);
    //time:Civil civil = time:utcToCivil(previoutime);
    // io:println(civil);
    // io:println("");
    // string timeString = time:utcToEmailString(previoutime).trim();
    // //io:println(timeString);
    // string[] splitcomma = regex:split(timeString.trim(),",");
    // string[] splitSpace = regex:split(splitcomma[1].trim()," ");
    // string timeBefore3Months = string:'join("-",splitSpace[0],splitSpace[1],splitSpace[2]);
    


    // time:Utc utc = time:utcNow();
    // time:Civil civil = time:utcToCivil(utc);
    // string created_time = civil.hour.toString() + ":" + civil.minute.toString() + ":" + (<int>civil.second).toString();
    // string created_date = civil.year.toString()+"-"+civil.month.toString() + "-" + civil.day.toString();
    // io:println(created_time);
    // io:println(created_date);
    //return timeBefore3Months;
    return previoutime;
};

// public function main() {
//     io:println(getThreeMonthsAgoDate());
// }

function checkDate(string date) returns boolean {
    string[] splittedDate = regex:split(date.trim(),"-");
    do {
	    int month = 4;//check int:fromString(splittedDate[1].trim());
        int year = 2023;//check int:fromString(splittedDate[2].trim());
        int day = 22;//check int:fromString(splittedDate[0].trim());
        time:Civil reportCivilTime = {month: month, hour: 0, year: year, day: day, minute: 0,utcOffset: {hours: 0,minutes: 0}};
        time:Utc reportUtcTime = check time:utcFromCivil(reportCivilTime);
        //time:Utc reportUtcTime = new time:Utc;
        
        time:Utc threeMonthsAgo = getThreeMonthsAgoDate();
        io:println("reportUtc: "+reportUtcTime.toString()+"\n");
        io:println("threeMonthUtc: "+threeMonthsAgo.toString()+"\n");
        if(threeMonthsAgo < reportUtcTime){
            return true;
        }else{
            return false;
        }
    } on fail var e {
    	io:println(e);
        return false;
    }
    
};