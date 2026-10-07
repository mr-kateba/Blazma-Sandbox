using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Core.Snapshots;

namespace Blazma.Storage;

/// <summary>The derived part of an analysis, stored as one gzip-compressed JSON document.</summary>
internal sealed class ReportDocument
{
    public StaticReport? Static { get; set; }
    public List<ProcessNode> ProcessRoots { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
    public RiskAssessment Risk { get; set; } = RiskAssessment.Empty;
    public List<BehaviorChain> Chains { get; set; } = [];
    public List<PersistenceDetection> Persistence { get; set; } = [];
    public List<Indicator> Indicators { get; set; } = [];
    public SnapshotDiff? SystemChanges { get; set; }
}
