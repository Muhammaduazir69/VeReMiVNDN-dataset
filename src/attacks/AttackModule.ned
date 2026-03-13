//
// VeReMiVNDN - Attack Module NED
//

package veremivndn.attacks;

//
// Interface for all attack modules
//
moduleinterface IAttackModule
{
    parameters:
        string attackType;
        double startTime @unit(s);
        double duration @unit(s);
        double intensity;
        string attackParams;
        @display("i=status/excl");

    gates:
        input ndnIn;
        output ndnOut;
}

//
// Base implementation of attack module
//
simple AttackModule like IAttackModule
{
    parameters:
        @class(veremivndn::AttackBase);
        string attackType = default("");
        double startTime @unit(s) = default(0s);
        double duration @unit(s) = default(0s);
        double intensity = default(0.5);
        string attackParams = default("");

        // Generic attack signals
        @signal[attackActive](type=long);
        @signal[attackIntensity](type=double);
        @signal[packetsGenerated](type=long);
        @signal[packetsModified](type=long);

        // Attack #1: InterestFlooding signals
        @signal[interestsFlooded](type=long);
        @signal[interestsCrafted](type=long);
        @signal[pitOccupancy](type=double);

        // Attack #2: ContentPoisoning signals
        @signal[contentPoisoned](type=long);
        @signal[bogusDataSent](type=long);

        // Attack #3: CachePollution signals
        @signal[pollutionRequest](type=long);
        @signal[cacheFilled](type=long);
        @signal[popularContent](type=long);

        // Attack #4: TimingAttack signals
        @signal[cacheHitDetected](type=long);
        @signal[probesSent](type=long);
        @signal[packetCaptured](type=long);

        // Attack #5: NamePrefixHijacking signals
        @signal[prefixHijacked](type=long);
        @signal[interestIntercepted](type=long);

        // Attack #6: SybilAmplification signals
        @signal[sybilRequest](type=long);
        @signal[identitySwitch](type=long);
        @signal[amplification](type=long);

        // Attack #7: ReplayAttack signals
        @signal[packetReplayed](type=long);
        @signal[fakeAuthenticPackets](type=long);

        // Attack #8: SelectiveForwarding signals
        @signal[packetDropped](type=long);
        @signal[packetDelayed](type=long);
        @signal[grayHoleActive](type=long);

        // Attack #9: Collusion signals
        @signal[synchronizedAction](type=long);
        @signal[coordinationMsg](type=long);

        // Attack #10: SignatureForgery signals
        @signal[signaturesForged](type=long);
        @signal[verificationFailures](type=long);

        // Attack #11: PrivacyDeanonymization signals
        @signal[privacyViolations](type=long);
        @signal[privacyViolation](type=long);
        @signal[locationsInferred](type=long);
        @signal[namesCollected](type=long);
        @signal[profilesBuilt](type=long);

        // Attack #12: InterestAggregation signals
        @signal[aggregationPrevented](type=long);
        @signal[pitImbalance](type=long);
        @signal[controlOverload](type=long);

        // Attack #13: CacheInvalidation signals
        @signal[versionsPublished](type=long);
        @signal[invalidationsSent](type=long);
        @signal[cacheChurn](type=long);

        // Attack #14: RadioJamming signals
        @signal[packetsJammed](type=long);
        @signal[jammingPower](type=double);
        @signal[channelOccupancy](type=double);

        // Attack #15: CachePrivacyLeakage signals
        @signal[snapshotsCollected](type=long);
        @signal[privacyLeakage](type=long);
        @signal[requestsLeaked](type=long);

        // Attack #16: ProducerImpersonation signals
        @signal[fakeDataProduced](type=long);
        @signal[impersonationSuccess](type=long);
        @signal[authBypass](type=long);

        // Attack #17: CachePartitioning signals
        @signal[relaysControlled](type=long);
        @signal[accessDenials](type=long);
        @signal[partitionStrength](type=double);

        // Attack #18: RoutingInfoFlood signals
        @signal[fibUpdatesFlooded](type=long);
        @signal[pitEntriesSpoofed](type=long);
        @signal[fakeRoutes](type=long);

        // Attack #19: NameEnumeration signals
        @signal[namesProbed](type=long);
        @signal[namesDiscovered](type=long);
        @signal[privacyCrawl](type=long);

        // Attack #20: MLEvasion signals
        @signal[adversarialExamples](type=long);
        @signal[evasionSuccess](type=long);
        @signal[featurePerturbation](type=double);

        // Statistics - ALL attack signals must have @statistic to be recorded
        @statistic[attackActive](record=vector);
        @statistic[packetsGenerated](record=count,sum);
        @statistic[packetsModified](record=count,sum);

        // Attack #1: InterestFlooding
        @statistic[interestsFlooded](source=interestsFlooded; record=count,sum);
        @statistic[interestsCrafted](source=interestsCrafted; record=count,sum);
        @statistic[pitOccupancy](source=pitOccupancy; record=vector,stats);

        // Attack #2: ContentPoisoning
        @statistic[contentPoisoned](source=contentPoisoned; record=count,sum);
        @statistic[bogusDataSent](source=bogusDataSent; record=count,sum);

        // Attack #3: CachePollution
        @statistic[pollutionRequest](source=pollutionRequest; record=count,sum);
        @statistic[cacheFilled](source=cacheFilled; record=count,sum);
        @statistic[popularContent](source=popularContent; record=count,sum);

        // Attack #4: TimingAttack
        @statistic[cacheHitDetected](source=cacheHitDetected; record=count,sum);
        @statistic[probesSent](source=probesSent; record=count,sum);
        @statistic[packetCaptured](source=packetCaptured; record=count,sum);

        // Attack #5: NamePrefixHijacking
        @statistic[prefixHijacked](source=prefixHijacked; record=count,sum);
        @statistic[interestIntercepted](source=interestIntercepted; record=count,sum);

        // Attack #6: SybilAmplification
        @statistic[sybilRequest](source=sybilRequest; record=count,sum);
        @statistic[identitySwitch](source=identitySwitch; record=count,sum);
        @statistic[amplification](source=amplification; record=count,sum);

        // Attack #7: ReplayAttack
        @statistic[packetReplayed](source=packetReplayed; record=count,sum);
        @statistic[fakeAuthenticPackets](source=fakeAuthenticPackets; record=count,sum);

        // Attack #8: SelectiveForwarding
        @statistic[packetDropped](source=packetDropped; record=count,sum);
        @statistic[packetDelayed](source=packetDelayed; record=count,sum);
        @statistic[grayHoleActive](source=grayHoleActive; record=count,sum);

        // Attack #9: Collusion
        @statistic[synchronizedAction](source=synchronizedAction; record=count,sum);
        @statistic[coordinationMsg](source=coordinationMsg; record=count,sum);

        // Attack #10: SignatureForgery
        @statistic[signaturesForged](source=signaturesForged; record=count,sum);
        @statistic[verificationFailures](source=verificationFailures; record=count,sum);

        // Attack #11: PrivacyDeanonymization
        @statistic[privacyViolations](source=privacyViolations; record=count,sum);
        @statistic[privacyViolation](source=privacyViolation; record=count,sum);
        @statistic[locationsInferred](source=locationsInferred; record=count,sum);
        @statistic[namesCollected](source=namesCollected; record=count,sum);
        @statistic[profilesBuilt](source=profilesBuilt; record=count,sum);

        // Attack #12: InterestAggregation
        @statistic[aggregationPrevented](source=aggregationPrevented; record=count,sum);
        @statistic[pitImbalance](source=pitImbalance; record=count,sum);
        @statistic[controlOverload](source=controlOverload; record=count,sum);

        // Attack #13: CacheInvalidation
        @statistic[versionsPublished](source=versionsPublished; record=count,sum);
        @statistic[invalidationsSent](source=invalidationsSent; record=count,sum);
        @statistic[cacheChurn](source=cacheChurn; record=count,sum);

        // Attack #14: RadioJamming
        @statistic[packetsJammed](source=packetsJammed; record=count,sum);
        @statistic[jammingPower](source=jammingPower; record=vector,stats);
        @statistic[channelOccupancy](source=channelOccupancy; record=vector,stats);

        // Attack #15: CachePrivacyLeakage
        @statistic[snapshotsCollected](source=snapshotsCollected; record=count,sum);
        @statistic[privacyLeakage](source=privacyLeakage; record=count,sum);
        @statistic[requestsLeaked](source=requestsLeaked; record=count,sum);

        // Attack #16: ProducerImpersonation
        @statistic[fakeDataProduced](source=fakeDataProduced; record=count,sum);
        @statistic[impersonationSuccess](source=impersonationSuccess; record=count,sum);
        @statistic[authBypass](source=authBypass; record=count,sum);

        // Attack #17: CachePartitioning
        @statistic[relaysControlled](source=relaysControlled; record=count,sum);
        @statistic[accessDenials](source=accessDenials; record=count,sum);
        @statistic[partitionStrength](source=partitionStrength; record=vector,stats);

        // Attack #18: RoutingInfoFlood
        @statistic[fibUpdatesFlooded](source=fibUpdatesFlooded; record=count,sum);
        @statistic[pitEntriesSpoofed](source=pitEntriesSpoofed; record=count,sum);
        @statistic[fakeRoutes](source=fakeRoutes; record=count,sum);

        // Attack #19: NameEnumeration
        @statistic[namesProbed](source=namesProbed; record=count,sum);
        @statistic[namesDiscovered](source=namesDiscovered; record=count,sum);
        @statistic[privacyCrawl](source=privacyCrawl; record=count,sum);

        // Attack #20: MLEvasion
        @statistic[adversarialExamples](source=adversarialExamples; record=count,sum);
        @statistic[evasionSuccess](source=evasionSuccess; record=count,sum);
        @statistic[featurePerturbation](source=featurePerturbation; record=vector,stats);

        @display("i=status/excl");

    gates:
        input ndnIn;
        output ndnOut;
}
