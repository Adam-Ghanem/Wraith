package assessment

// TaskNetworkPortDiscovery is the single R13 task type owned by the NPD-1
// adapter. It is intentionally not added to the generic web assessment
// profile planner; callers must construct an explicitly authorized network
// assessment task.
const TaskNetworkPortDiscovery TaskType = "network_port_discovery"
