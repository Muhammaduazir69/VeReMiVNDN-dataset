package veremivndn.dpids.controller;

simple DPIDSController
{
    parameters:
        @class(veremivndn::DPIDSController);
        double orchestrationInterval @unit(s) = default(1s);
        double beliefThreshold = default(0.6);
        bool enablePenalization = default(true);
        bool enableExtendedMonitoring = default(true);

        // Canvas anchor of the DP-IDS dashboard panel (380x280 units), in
        // playground units. Only rsu[0] draws it; park it in free canvas so it
        // does not cover an RSU icon.
        double dashX = default(50);
        double dashY = default(50);
        double extendedMonitoringDuration @unit(s) = default(10s);

        @signal[vehiclesMonitored](type=long);
        @signal[vehiclesDetected](type=long);
        @signal[vehiclesPenalized](type=long);

        @statistic[vehiclesMonitored](record=vector,stats);
        @statistic[vehiclesDetected](record=count,vector);
        @statistic[vehiclesPenalized](record=count,vector);

        @display("i=block/control,red");
}
