//import ballerina/log;
import ballerina/time;
import ballerina/io;
import ballerina/http;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;

final cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
final cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

final string[] severityList = ["critical","high","medium","low"];
final string[] resolutionList = ["total","falsePositive","truePositive","batchForPatching","notAThreat","notApplicable", "inadequateInfo","alreadyMitigated","fixed","notAssigned"];

service / on new http:Listener(8090) {
    resource function get rawTrivyScanData() returns json |error {

        string query = string `SELECT c.assetOrWebsite,c.assetVersion,c.url,c.critical,c.high,c.medium,c.low,c.createdDate,c.reportID,c.tags,c.team FROM c  WHERE c.scannerName = 'trivy'`;
        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<record {}, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "summaryContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        //JsonCompleteVulnerability[] outputs = check from JsonCompleteVulnerability vulnRecord in result  select vulnRecord;
        json[] outputs = check from record {} rec in result select rec.toJson();

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        return { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
    }
    resource function get summaryTrivyScanData() returns json |error {

        string query = string `SELECT c.assetOrWebsite,c.assetVersion,c.url,c.critical,c.high,c.medium,c.low,c.createdDate,c.reportID,c.tags,c.team FROM c  WHERE c.scannerName = 'trivy'`;
        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<record {}, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "summaryContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        //JsonCompleteVulnerability[] outputs = check from JsonCompleteVulnerability vulnRecord in result  select vulnRecord;
        json[] outputs = check from record {} rec in result select rec.toJson();

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        return { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
    }

    resource function get tabularSummaryTrivyScanData() returns json |error {

        string query = string `SELECT c.assetOrWebsite,c.assetVersion,c.url,c.critical,c.high,c.medium,c.low,c.createdDate,c.reportID,c.tags,c.team FROM c  WHERE c.scannerName = 'trivy'`;
        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<SummaryRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "summaryContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        //JsonCompleteVulnerability[] outputs = check from JsonCompleteVulnerability vulnRecord in result  select vulnRecord;
        json[] outputs = [];
        check result.forEach(function(SummaryRecord summaryRecord) {
            foreach string severity in severityList {
                SeverityResoutionDetails srDetails = <SeverityResoutionDetails>summaryRecord.get(severity);
                foreach string resolution in resolutionList {
                    FormattedSummaryRecord newSummaryRecord = {};
                    newSummaryRecord.scannedDate = summaryRecord.scannedDate;
                    newSummaryRecord.scannerName = summaryRecord.scannerName;
                    newSummaryRecord.assetOrWebsite = summaryRecord.assetOrWebsite;
                    newSummaryRecord.assetVersion = summaryRecord.assetVersion;
                    newSummaryRecord.scanId = summaryRecord.scanId;
                    newSummaryRecord.url = summaryRecord.url;
                    newSummaryRecord.linkToVms = summaryRecord.linkToVms;
                    newSummaryRecord.tags = summaryRecord.tags;
                    newSummaryRecord.createdTime = summaryRecord.createdTime;
                    newSummaryRecord.createdDate = summaryRecord.createdDate;
                    newSummaryRecord.team = summaryRecord.team;
                    newSummaryRecord.reportID = summaryRecord.reportID;
                    newSummaryRecord.status = summaryRecord.status; 
                    newSummaryRecord.status_changed_on = summaryRecord.status_changed_on;
                    newSummaryRecord.status_changed_by = summaryRecord.status_changed_by;
                    newSummaryRecord.severityResoutionType = severity+resolution;
                    newSummaryRecord.vulnerabilityCount = srDetails.get(resolution);

                    outputs.push(newSummaryRecord);
                }
            }

            
        });

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        return { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
    }
}
