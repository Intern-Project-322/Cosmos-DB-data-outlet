import ballerina/log;
import ballerina/time;
import ballerina/io;
import ballerina/http;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;


service / on new http:Listener(8090) {
    resource function get invictiScanList() returns json|error {
        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

        string query = string `SELECT c.asset,c.team,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;

        json[] outputs = [];

        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<ScanRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        check result.forEach(function(ScanRecord scanRecord){
            Vulnerability[] vulnerabilityList = scanRecord.vulnerabilities;
            vulnerabilityList.forEach(function(Vulnerability vuln){
                CompleteVulnerability compRecord = {
                    asset: scanRecord.asset,
                    team: scanRecord.team,
                    title: vuln.title,
                    description: vuln.description,
                    severity: vuln.severity,
                    url: vuln.url,
                    cve: vuln.cve,
                    component_name: vuln.component_name,
                    component_path: vuln.component_path,
                    component_type: vuln.component_name
                };
                outputs.push(compRecord.toJson());
            });
        });

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        json finalOutput = { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
        return finalOutput;
    }
    resource function get rawScanData() returns json |error {
        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

        string query = string `SELECT c.asset,c.team,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;

        json[] outputs = [];
        json[] testingOutputs = [];
        boolean isError = false;

        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

       stream<ScanRecord,error?>|error result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);


       if(result is stream<ScanRecord,error?>){
            error? e = result.forEach( function(ScanRecord queryResult) {
                            log:printInfo(queryResult.toString());
                            testingOutputs.push(queryResult.toJson());
            });
            if (e is error) {
                        log:printInfo(msg = e.message());
                        outputs.push({status:"error in for loop"});
                        isError = true;
            }else {
                outputs.push(e.toJson());
            }
       }else{
        outputs.push({status:"error"});
       }
       
       if(!isError){
            outputs = testingOutputs;
       }
        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        json finalOutput = { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
        return finalOutput;
    }
}

//https://ballerina.io/learn/by-example/time-utc/


