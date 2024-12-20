package apikeys

import (
	pb "argus-core/rpc/apikeys"
	"fmt"
)

func validateCreateAPIKeyRequest(req *pb.CreateAPIKeyRequest) error {
    if req.Name == "" {
        return fmt.Errorf("name is required")
    }
    if len(req.Name) > 255 {
        return fmt.Errorf("name must be less than 256 characters")
    }
    return nil
}
