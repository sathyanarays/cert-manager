package cmp

import (
	"context"
	"fmt"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

const (
	successReady = "IsReady"
)

func (c *Cmp) Setup(ctx context.Context) error {
	fmt.Println("## CMP Setup called")
	apiutil.SetIssuerCondition(c.issuer, c.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionTrue, successReady, "")
	return nil
}
