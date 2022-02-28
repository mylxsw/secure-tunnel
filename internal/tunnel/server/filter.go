package server

import (
	"bytes"
	"github.com/mongodb/mongonet"
	"github.com/mylxsw/secure-tunnel/internal/protocol/mysql"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/hub"
	"strings"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/secmask/go-redisproto"
)

func defaultProtocolFilter(link *hub.Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {

}

// TODO 无法使用，可能是存在粘包问题
func mongoProtocolFilter(link *hub.Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	message, err := mongonet.ReadMessageFromBytes(data)
	if err != nil {
		log.With(authedUser).Errorf("parse mongo protocol failed: %v", err)
		return
	}

	switch message.Header().OpCode {
	case mongonet.OP_MSG, mongonet.OP_MSG_LEGACY:
		msg := message.(*mongonet.MessageMessage)
		bodyDoc, err := msg.BodyDoc()
		if err != nil {
			log.With(authedUser).Errorf("parse mongo protocol failed: %v", err)
			return
		}
		data := bodyDoc.String()
		if strings.Contains(data, `"find":`) ||
			strings.Contains(data, `"insert":`) ||
			strings.Contains(data, `"update":`) ||
			strings.Contains(data, `"delete":`) {

			log.WithFields(log.Fields{
				"user":    authedUser.ToLogEntry(),
				"backend": backend.Backend,
				"link":    link.ID,
				"data":    bodyDoc.String(),
				"type":    "OP_MSG",
			}).Info("audit")
		}

	case mongonet.OP_INSERT:
		msg := message.(*mongonet.InsertMessage)
		var data []interface{}
		for _, doc := range msg.Docs {
			d, _ := doc.ToBSOND()
			data = append(data, d)
		}

		log.WithFields(log.Fields{
			"user":      authedUser.ToLogEntry(),
			"backend":   backend.Backend,
			"link":      link.ID,
			"data":      data,
			"namespace": msg.Namespace,
			"type":      "OP_INSERT",
		}).Info("audit")
	case mongonet.OP_QUERY:
		msg := message.(*mongonet.QueryMessage)

		proj, _ := msg.Project.ToBSOND()
		query, _ := msg.Query.ToBSOND()

		log.WithFields(log.Fields{
			"user":      authedUser.ToLogEntry(),
			"backend":   backend.Backend,
			"link":      link.ID,
			"project":   proj,
			"query":     query,
			"namespace": msg.Namespace,
			"type":      "OP_QUERY",
		}).Info("audit")
	}
}

func mysqlProtocolFilter(link *hub.Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	message := mysql.PacketResolve(data)
	if message != "" {
		log.WithFields(log.Fields{
			"user":    authedUser.ToLogEntry(),
			"backend": backend.Backend,
			"link":    link.ID,
			"data":    message,
		}).Info("audit")
	}
}

func redisProtocolFilter(link *hub.Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	cmd, err := redisproto.NewParser(bytes.NewBuffer(data)).ReadCommand()
	if err != nil {
		log.With(authedUser).Errorf("parse redis protocol failed: %v", err)
		return
	}

	strs := make([]string, 0)
	for i := 0; i < cmd.ArgCount(); i++ {
		strs = append(strs, string(cmd.Get(i)))
	}

	log.WithFields(log.Fields{
		"user":    authedUser.ToLogEntry(),
		"backend": backend.Backend,
		"link":    link.ID,
		"data":    strings.Join(strs, " "),
	}).Info("audit")
}
