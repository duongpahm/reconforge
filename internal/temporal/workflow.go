package temporal

import (
	"time"

	"go.temporal.io/sdk/workflow"
)

// ScanInput represents the input for a ScanWorkflow.
type ScanInput struct {
	Target string
	Mode   string
	Config []byte // Pass config as serialized JSON/YAML or just pass path
}

// ScanResult represents the output of a ScanWorkflow.
type ScanResult struct {
	Target   string
	Findings int
}

// ScanWorkflow is the durable temporal workflow for orchestrating recon modules.
func ScanWorkflow(ctx workflow.Context, input ScanInput) (*ScanResult, error) {
	// Set default activity options
	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		// Recon tools can fail due to transient network issues, we want to retry them
		// RetryPolicy is default by Temporal (exponential backoff)
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	logger := workflow.GetLogger(ctx)
	logger.Info("Starting ReconForge ScanWorkflow", "target", input.Target, "mode", input.Mode)

	// A full implementation would construct a DAG and execute activities in topological order.
	// We'll mimic the DAG using workflow.Go for parallel stages.

	var a *Activities

	// Example: OSINT Phase
	var osintFindings int
	err := workflow.ExecuteActivity(ctx, a.RunOSINT, input.Target).Get(ctx, &osintFindings)
	if err != nil {
		logger.Error("OSINT phase failed", "error", err)
		return nil, err
	}

	// Example: Subdomain Phase
	var subFindings int
	err = workflow.ExecuteActivity(ctx, a.RunSubdomain, input.Target).Get(ctx, &subFindings)
	if err != nil {
		logger.Error("Subdomain phase failed", "error", err)
		return nil, err
	}

	return &ScanResult{
		Target:   input.Target,
		Findings: osintFindings + subFindings,
	}, nil
}
