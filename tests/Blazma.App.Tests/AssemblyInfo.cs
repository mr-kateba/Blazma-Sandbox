// The interface language (Loc.Instance) is one global object: tests that read or switch it must
// not run at the same time, or one test sees the language another test just selected.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
