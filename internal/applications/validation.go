package applications

import (
	pb "argus-core/rpc/applications"
	"fmt"
)

func validateCreateApplicationRequest(req *pb.CreateApplicationRequest) error {
    if req.Name == "" {
        return fmt.Errorf("name is required")
    }
    if len(req.Name) > 255 {
        return fmt.Errorf("name must be less than 256 characters")
    }
    if len(req.Description) > 1000 {
        return fmt.Errorf("description must be less than 1000 characters")
    }
    return nil
}

func validateUpdateApplicationRequest(req *pb.UpdateApplicationRequest) error {
    if req.ApplicationId == "" {
        return fmt.Errorf("application ID is required")
    }
    if req.Name == "" {
        return fmt.Errorf("name is required")
    }
    if len(req.Name) > 255 {
        return fmt.Errorf("name must be less than 256 characters")
    }
    if len(req.Description) > 1000 {
        return fmt.Errorf("description must be less than 1000 characters")
    }
    return nil
}
