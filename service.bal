import ballerina/log;
import ballerina/io;
import ballerinax/azure_cosmosdb as cosmosdb;
configurable config cosmosConfig =?;

public function main() returns error?{
    cosmosdb:ConnectionConfig configuration = {
        baseUrl: cosmosConfig.baseUrl,
        primaryKeyOrResourceToken:cosmosConfig.primaryKey
    };
    cosmosdb:DataPlaneClient azureCosmosClient = check new (configuration);

    string query = string `SELECT c.reportId,c.vulnerabilities FROM vmsContainer c WHERE c.scanner_type = 'trivy'`;

    stream<record{}, error?> result = check azureCosmosClient->queryDocuments("vmsDB", "vmsContainer", query);
    check result.forEach(isolated function(record {} queryResult) {
        io:println(queryResult.toString());
    });
    log:printInfo("Success!");
}


// stream<record{}, error?> result = check azureCosmosClient->getDocumentList("SampleDB", "SampleContainer", "");
    // check result.forEach(function (record {} document) {
    //    io:println(document.toString());
    // });
    // log:printInfo("Success!");

    // string query = string `SELECT f.name, f.description FROM SampleContainer f WHERE f.categoryName = 'Clothing, Tights'`;

    // stream<record{}, error?> result = check azureCosmosClient->queryDocuments("SampleDB", "SampleContainer", query);
    // check result.forEach(isolated function(record {} queryResult) {
    //     io:println(queryResult.toString());
    // });
    // log:printInfo("Success!");




