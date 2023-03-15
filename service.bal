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

service / on new http:Listener(8090) {
    resource function get rawTrivyScanData() returns json |error {

        string query = string `SELECT c.asset,c.team,t.title,t.description,t.severity,t.cve,t.url,t.component_name,t.component_path,t.component_type FROM c JOIN t IN c.vulnerabilities WHERE c.scanner_type = 'trivy'`;

        time:Utc beforeFetching = time:utcNow();
        int timeBeforeFetching= beforeFetching[0];
        io:println(`Number of seconds before fetching: ${beforeFetching[0]}s`);

        stream<JsonCompleteVulnerability, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
       
        time:Utc afterFetching = time:utcNow();
        int timeafterFetching= afterFetching[0];
        io:println(`Number of seconds after fetching: ${afterFetching[0]}s`);

        JsonCompleteVulnerability[] outputs = check from JsonCompleteVulnerability vulnRecord in result  select vulnRecord;

        time:Utc afterParsing = time:utcNow();
        int timeafterParsing= afterParsing[0];
        io:println(`Number of seconds after Parsing: ${afterParsing[0]}s`);

        return { "beforeFetching":timeBeforeFetching,
                             "afterFetching":timeafterFetching,
                             "afterParsing":timeafterParsing,
                             "results":outputs};
    }
}
