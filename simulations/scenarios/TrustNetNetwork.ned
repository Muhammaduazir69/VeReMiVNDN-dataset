//
// VeReMiVNDN - TrustNet evaluation network
//
// Reuses the purpose-built UrbanVndnNetwork (all VNDN parameters, RSUs, SUMO
// mobility manager, TRIDENT control-plane singletons) and adds the global
// TrustNetCollector that exports per-vehicle, per-window behavioural features
// for the TrustNet detector.
//
package veremivndn.simulations.scenarios;

import veremivndn.ids.collection.TrustNetCollector;

network TrustNetNetwork extends UrbanVndnNetwork
{
    submodules:
        trustnetCollector: TrustNetCollector {
            @display("p=800,10500;i=block/table2,#1f77b4");
        }
}
