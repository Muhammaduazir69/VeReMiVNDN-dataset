package veremivndn.ids.logging;

simple DataCollector
{
    parameters:
        @class(veremivndn::DataCollector);
        @display("i=block/table2");

        // Configuration
        string outputFormat = default("csv");  // "csv", "json", "arff"
        string outputDirectory = default("datasets");
        string datasetName = default("vndn_attack_dataset");
        bool realtimeExport = default(false);
        int bufferSize = default(1000);
        bool includeHeader = default(true);
        bool normalizeFeatures = default(false);

        // Timing
        double collectionInterval @unit(s) = default(1s);
        double exportInterval @unit(s) = default(60s);

        // Signals
        @signal[dataCollected](type=long);
        @signal[dataExported](type=long);

        @statistic[dataCollected](title="Data Records Collected"; record=count,vector);
        @statistic[dataExported](title="Data Records Exported"; record=count,vector);
}
