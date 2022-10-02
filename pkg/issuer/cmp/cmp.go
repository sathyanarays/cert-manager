package cmp

import (
	"fmt"

	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

type Cmp struct {
	*controller.Context
	issuer v1.GenericIssuer

	secretsLister corelisters.SecretLister
}

func New(ctx *controller.Context, issuer v1.GenericIssuer) (issuer.Interface, error) {
	fmt.Println("## CMP New called")
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

	return &Cmp{
		Context:       ctx,
		issuer:        issuer,
		secretsLister: secretsLister,
	}, nil
}

// Register this Issuer with the issuer factory
func init() {
	fmt.Println("Registering cmp issuer")
	issuer.RegisterIssuer(apiutil.IssuerCmp, New)
}
