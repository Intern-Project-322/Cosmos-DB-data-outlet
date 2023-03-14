import ballerina/time;
import ballerina/http;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;


service / on new http:Listener(8090) {
    resource function get rawScanData() returns json |error {
        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

        string query = string `SELECT c.asset,c.team,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;
        json[] outputs = [];

        time:Utc beforeFetching = time:utcNow();
        int timebeforeFetching= beforeFetching[0];

        stream<ScanRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        check azureCosmosClient->close();
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];

        check result.forEach(function(ScanRecord scanRecord){
           outputs.push(scanRecord);
        });

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];

        return { "NonJson":false,
                "TimeBeforeFetching":timebeforeFetching,
                "TimeAfterFetching":timeafterFetching,
                "TimeAfterParsing":timeafterParsing,
                "results":outputs};
    }

    resource function get nonJsonScanData() returns json |error {
        cosmosdb:ConnectionConfig configuration = {
            baseUrl: cosmosConfig.baseUrl,
            primaryKeyOrResourceToken:cosmosConfig.primaryKey
        };
        cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

        string query = string `SELECT c.asset,c.team,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;
        json[] outputs = [];

        time:Utc beforeFetching = time:utcNow();
        int timebeforeFetching= beforeFetching[0];

        stream<NonJsonScanRecord, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        check azureCosmosClient->close();

        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];

        check result.forEach(function(NonJsonScanRecord scanRecord){
           outputs.push(scanRecord.toJson());
        });

        time:Utc afterParsingToJson = time:utcNow();
        int timeafterParsingToJson= afterParsingToJson[0];

        return { "NonJson":true,
                "TimeBeforeFetching":timebeforeFetching,
                "TimeAfterFetching":timeafterFetching,
                "TimeAfterParsing":timeafterParsingToJson,
                "results":outputs};
    }
}