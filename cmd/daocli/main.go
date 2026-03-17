package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	daov1 "dao.pub/gen/dao/v1"
	"dao.pub/gen/dao/v1/daov1connect"
	"dao.pub/internal/auth"

	"connectrpc.com/connect"
)

type localIdentity struct {
	IdentityID string `json:"identity_id"`
	PublicKey   string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func main() {
	addr := "http://localhost:8080"
	if env := os.Getenv("DAO_ADDR"); env != "" {
		addr = env
	}

	client := daov1connect.NewDaoServiceClient(http.DefaultClient, addr)
	ctx := context.Background()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ping":
		res, err := client.Ping(ctx, connect.NewRequest(&daov1.PingRequest{}))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s (timestamp: %d)\n", res.Msg.Message, res.Msg.Timestamp)

	case "register":
		if len(os.Args) < 4 {
			log.Fatal("usage: daocli register <name> <github>")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		res, err := client.Register(ctx, connect.NewRequest(&daov1.RegisterRequest{
			Name:      os.Args[2],
			Github:    os.Args[3],
			PublicKey: pub,
			KeyLabel:  "default",
		}))
		if err != nil {
			log.Fatal(err)
		}
		id := res.Msg.Identity
		if err := saveIdentity(&localIdentity{
			IdentityID: id.Id,
			PublicKey:  hex.EncodeToString(pub),
			PrivateKey: hex.EncodeToString(priv),
		}); err != nil {
			log.Printf("warning: could not save identity: %v", err)
		}
		fmt.Printf("registered: %s (%s)\n", id.Name, id.Id)
		fmt.Printf("kind: %s\n", id.Kind)
		fmt.Printf("keypair saved to %s\n", identityPath())

	case "whoami":
		req := connect.NewRequest(&daov1.WhoAmIRequest{})
		signReq(req, "/dao.v1.DaoService/WhoAmI")
		res, err := client.WhoAmI(ctx, req)
		if err != nil {
			log.Fatal(err)
		}
		printIdentity(res.Msg.Identity)

	case "create":
		// daocli create agent <name> [description]
		// daocli create org <name> [description]
		if len(os.Args) < 4 {
			log.Fatal("usage: daocli create <agent|org> <name> [description]")
		}
		kindStr := os.Args[2]
		name := os.Args[3]
		desc := ""
		if len(os.Args) > 4 {
			desc = os.Args[4]
		}

		switch kindStr {
		case "agent":
			req := connect.NewRequest(&daov1.CreateAgentRequest{
				Name:        name,
				Description: desc,
			})
			signReq(req, "/dao.v1.DaoService/CreateAgent")
			res, err := client.CreateAgent(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			printIdentity(res.Msg.Identity)
		case "org":
			req := connect.NewRequest(&daov1.CreateOrgRequest{
				Name:        name,
				Description: desc,
			})
			signReq(req, "/dao.v1.DaoService/CreateOrg")
			res, err := client.CreateOrg(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			printIdentity(res.Msg.Identity)
		default:
			log.Fatalf("unknown kind: %s (use agent or org)", kindStr)
		}

	case "owned":
		// daocli owned [user|org]
		var kind daov1.IdentityKind
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "user", "agent":
				kind = daov1.IdentityKind_IDENTITY_KIND_USER
			case "org":
				kind = daov1.IdentityKind_IDENTITY_KIND_ORG
			}
		}
		req := connect.NewRequest(&daov1.ListOwnedRequest{Kind: kind})
		signReq(req, "/dao.v1.DaoService/ListOwned")
		res, err := client.ListOwned(ctx, req)
		if err != nil {
			log.Fatal(err)
		}
		for _, id := range res.Msg.Identities {
			fmt.Printf("%-8s %-20s %s\n", kindLabel(id), id.Name, id.Id)
		}
		if len(res.Msg.Identities) == 0 {
			fmt.Println("(none)")
		}

	case "members":
		// daocli members <group_id>
		// daocli members add <group_id> <member_id> [role]
		// daocli members remove <group_id> <member_id>
		if len(os.Args) < 3 {
			log.Fatal("usage: daocli members <group_id>")
		}

		switch os.Args[2] {
		case "add":
			if len(os.Args) < 5 {
				log.Fatal("usage: daocli members add <group_id> <member_id> [role]")
			}
			role := "member"
			if len(os.Args) > 5 {
				role = os.Args[5]
			}
			req := connect.NewRequest(&daov1.AddMemberRequest{
				GroupId:  os.Args[3],
				MemberId: os.Args[4],
				Role:     role,
			})
			signReq(req, "/dao.v1.DaoService/AddMember")
			res, err := client.AddMember(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			m := res.Msg.Membership
			fmt.Printf("added %s to %s as %s\n", m.IdentityId, m.GroupId, m.Role)

		case "remove":
			if len(os.Args) < 5 {
				log.Fatal("usage: daocli members remove <group_id> <member_id>")
			}
			req := connect.NewRequest(&daov1.RemoveMemberRequest{
				GroupId:  os.Args[3],
				MemberId: os.Args[4],
			})
			signReq(req, "/dao.v1.DaoService/RemoveMember")
			_, err := client.RemoveMember(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("member removed")

		default:
			// list members of group
			groupID := os.Args[2]
			req := connect.NewRequest(&daov1.ListMembersRequest{GroupId: groupID})
			signReq(req, "/dao.v1.DaoService/ListMembers")
			res, err := client.ListMembers(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			for _, m := range res.Msg.Members {
				fmt.Printf("%-20s %s\n", m.IdentityId, m.Role)
			}
			if len(res.Msg.Members) == 0 {
				fmt.Println("(no members)")
			}
		}

	case "identity":
		if len(os.Args) < 3 {
			log.Fatal("usage: daocli identity <id>")
		}
		req := connect.NewRequest(&daov1.GetIdentityRequest{Id: os.Args[2]})
		signReq(req, "/dao.v1.DaoService/GetIdentity")
		res, err := client.GetIdentity(ctx, req)
		if err != nil {
			log.Fatal(err)
		}
		printIdentity(res.Msg.Identity)

	case "keys":
		if len(os.Args) < 3 {
			req := connect.NewRequest(&daov1.ListKeysRequest{})
			signReq(req, "/dao.v1.DaoService/ListKeys")
			res, err := client.ListKeys(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			for _, k := range res.Msg.Keys {
				status := "active"
				if k.Revoked {
					status = "revoked"
				}
				fmt.Printf("%s  %-12s  %s\n", k.Id, k.Label, status)
			}
			return
		}
		switch os.Args[2] {
		case "revoke":
			if len(os.Args) < 4 {
				log.Fatal("usage: daocli keys revoke <key_id>")
			}
			req := connect.NewRequest(&daov1.RevokeKeyRequest{KeyId: os.Args[3]})
			signReq(req, "/dao.v1.DaoService/RevokeKey")
			_, err := client.RevokeKey(ctx, req)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("key revoked")
		}

	case "reputation":
		if len(os.Args) < 3 {
			log.Fatal("usage: daocli reputation <id>")
		}
		req := connect.NewRequest(&daov1.GetReputationRequest{IdentityId: os.Args[2]})
		signReq(req, "/dao.v1.DaoService/GetReputation")
		res, err := client.GetReputation(ctx, req)
		if err != nil {
			log.Fatal(err)
		}
		r := res.Msg.Reputation
		fmt.Printf("score: %d\ntotal_calls: %d\nsuccessful: %d\n", r.Score, r.TotalCalls, r.SuccessfulCalls)

	default:
		fmt.Printf("unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("usage: daocli <command> [args]")
	fmt.Println()
	fmt.Println("public:")
	fmt.Println("  ping                                  health check")
	fmt.Println("  register <name> <github>              create user identity")
	fmt.Println()
	fmt.Println("identity:")
	fmt.Println("  whoami                                show current identity")
	fmt.Println("  create <agent|org> <name> [desc]      create agent or org")
	fmt.Println("  owned [agent|org]                     list owned identities")
	fmt.Println("  identity <id>                         look up any identity")
	fmt.Println()
	fmt.Println("membership:")
	fmt.Println("  members <group_id>                    list members")
	fmt.Println("  members add <group_id> <id> [role]    add member")
	fmt.Println("  members remove <group_id> <id>        remove member")
	fmt.Println()
	fmt.Println("keys:")
	fmt.Println("  keys                                  list your public keys")
	fmt.Println("  keys revoke <key_id>                  revoke a key")
	fmt.Println()
	fmt.Println("reputation:")
	fmt.Println("  reputation <id>                       check reputation")
}

func printIdentity(id *daov1.Identity) {
	fmt.Printf("id:    %s\n", id.Id)
	fmt.Printf("kind:  %s\n", kindLabel(id))
	fmt.Printf("name:  %s\n", id.Name)
	if id.Description != "" {
		fmt.Printf("desc:  %s\n", id.Description)
	}
	if id.Github != "" {
		fmt.Printf("github: %s\n", id.Github)
	}
	if id.OwnerId != "" {
		fmt.Printf("owner: %s\n", id.OwnerId)
	}
}

func kindLabel(id *daov1.Identity) string {
	switch id.Kind {
	case daov1.IdentityKind_IDENTITY_KIND_USER:
		if id.UserType == daov1.UserType_USER_TYPE_AGENT {
			return "agent"
		}
		return "human"
	case daov1.IdentityKind_IDENTITY_KIND_ORG:
		return "org"
	default:
		return "unknown"
	}
}

// --- identity file management ---

func identityPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dao", "identity.json")
}

func saveIdentity(li *localIdentity) error {
	dir := filepath.Dir(identityPath())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(li, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(identityPath(), data, 0600)
}

func loadIdentity() *localIdentity {
	data, err := os.ReadFile(identityPath())
	if err != nil {
		return nil
	}
	var li localIdentity
	if err := json.Unmarshal(data, &li); err != nil {
		return nil
	}
	return &li
}

func signReq[T any](req *connect.Request[T], procedure string) {
	li := loadIdentity()
	if li == nil {
		log.Fatal("not registered — run: daocli register <name> <github>")
	}
	privBytes, err := hex.DecodeString(li.PrivateKey)
	if err != nil {
		log.Fatal("corrupt identity file")
	}
	signer := auth.NewSigner(ed25519.PrivateKey(privBytes))
	signer.Sign(req, procedure)
}
