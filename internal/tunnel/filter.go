package tunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/protocol/mysql"
	"github.com/secmask/go-redisproto"
)

func defaultProtocolFilter(isResp bool, link *Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	if isResp {
		if backend.Backend.LogResponse {
			log.WithFields(log.Fields{
				"user":    authedUser,
				"backend": backend.Backend,
				"link":    link.id,
				"data":    string(data),
			}).Info("audit:resp")
		}
	} else {
		log.WithFields(log.Fields{
			"user":    authedUser,
			"backend": backend.Backend,
			"link":    link.id,
			"data":    string(data),
		}).Info("audit:req")
	}
}

func mysqlProtocolFilter(isResp bool, link *Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	if isResp {
		if backend.Backend.LogResponse {
			log.WithFields(log.Fields{
				"user":    authedUser,
				"backend": backend.Backend,
				"link":    link.id,
				"data":    string(data),
			}).Info("audit:resp")
		}
	} else {
		var builder strings.Builder
		packets := mysql.DeserializePacket(data)
		for _, packet := range packets {
			switch packet.GetCommandType() {
			case mysql.COM_INIT_DB:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(mysql.ComInitDb).SchemaName))
			case mysql.COM_QUERY:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(mysql.ComQuery).Query))
			case mysql.COM_FIELD_LIST:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(mysql.ComFieldList).Table))
			case mysql.COM_CREATE_DB:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(mysql.ComCreateDb).SchemaName))
			case mysql.COM_DROP_DB:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(mysql.ComDropDb).SchemaName))
			case mysql.COM_REFRESH:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(packet.(mysql.ComRefresh).SubCommand)))
			case mysql.COM_SHUTDOWN:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(packet.(mysql.ComShutdown).SubCommand)))
			case mysql.COM_PROCESS_KILL:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), strconv.Itoa(packet.(mysql.ComProcessKill).ConnectionID)))
			case mysql.COM_CHANGE_USER:
				user := packet.(mysql.ComChangeUser)
				data, _ := json.Marshal(map[string]interface{}{
					"auth_plugin_name": user.AuthPluginName,
					"auth_response":    user.AuthResponse,
					"chacter_set":      user.CharacterSet,
					"schema":           user.SchemaName,
					"user":             user.User,
					"data":             user.Data,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_BINLOG_DUMP:
				pack := packet.(mysql.ComBinlogDump)
				data, _ := json.Marshal(map[string]interface{}{
					"binlog_file_name": pack.BinlogFileName,
					"binlog_position":  pack.BinlogPosition,
					"server_id":        pack.ServerID,
					"flag":             pack.Flag,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_TABLE_DUMP:
				pack := packet.(mysql.ComTableDump)
				data, _ := json.Marshal(map[string]interface{}{
					"database": pack.DatabaseName,
					"table":    pack.TableName,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_REGISTER_SLAVE:
				pack := packet.(mysql.ComRegisterSlave)
				data, _ := json.Marshal(map[string]interface{}{
					"master_id":        pack.MasterID,
					"replication_rank": pack.ReplicationRank,
					"server_id":        pack.ServerID,
					"slave_hostname":   pack.SlavesHostName,
					"slave_mysql_port": pack.SlavesMySQLPort,
					"slave_user":       pack.SlavesUser,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_STMT_PREPARE:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(mysql.ComSTMTPrepare).Query))
			case mysql.COM_STMT_EXECUTE:
				pack := packet.(mysql.ComSTMTExecute)
				data, _ := json.Marshal(map[string]interface{}{
					"stmtid":                 pack.STMTID,
					"flags":                  pack.Flags,
					"iteration_count":        pack.IterationCount,
					"null_bitmap":            pack.NULLBitmap,
					"new_params_bound_flag":  pack.NewParamsBoundFlag,
					"typeof_each_parameter":  pack.TypeOfEachParameter,
					"valueof_each_parameter": pack.ValueOfEachParameter,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_STMT_SEND_LONG_DATA:
				pack := packet.(mysql.ComSTMTSendLongData)
				data, _ := json.Marshal(map[string]interface{}{
					"statement_id": pack.StatementID,
					"param_id":     pack.ParamID,
					"data":         pack.Data,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_STMT_CLOSE:
				pack := packet.(mysql.ComSTMTClose)
				data, _ := json.Marshal(map[string]interface{}{
					"statement_id": pack.StatementID,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_STMT_RESET:
				pack := packet.(mysql.ComSTMTReset)
				data, _ := json.Marshal(map[string]interface{}{
					"statement_id": pack.StatementID,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_SET_OPTION:
				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(packet.(mysql.ComSetOption).ComSetOptionOperation)))
			case mysql.COM_STMT_FETCH:
				pack := packet.(mysql.ComSTMTFetch)
				data, _ := json.Marshal(map[string]interface{}{
					"stmtid":   pack.STMTID,
					"num_rows": pack.NumRows,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_BINLOG_DUMP_GTID:
				pack := packet.(mysql.ComBinlogDumpGTID)
				data, _ := json.Marshal(map[string]interface{}{
					"flags":           pack.Flags,
					"server_id":       pack.ServerID,
					"binlog_filename": pack.BinlogFilename,
					"binlog_position": pack.BinlogPosition,
					"data":            pack.Data,
				})

				builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
			case mysql.COM_RESET_CONNECTION:
			case mysql.COM_SLEEP:
			case mysql.COM_QUIT:
			case mysql.COM_DEBUG:
			case mysql.COM_PING:
			case mysql.COM_TIME:
			case mysql.COM_DELAYED_INSERT:
			case mysql.COM_STATISTICS:
			case mysql.COM_PROCESS_INFO:
			case mysql.COM_CONNECT:
			case mysql.COM_CONNECT_OUT:
			case mysql.COM_DAEMON:
			}

		}

		message := strings.Trim(builder.String(), "\n\r ")
		if message != "" {
			log.WithFields(log.Fields{
				"user":    authedUser,
				"backend": backend.Backend,
				"link":    link.id,
				"data":    message,
			}).Info("audit:req")
		}
	}
}

func redisProtocolFilter(isResp bool, link *Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	if isResp {
		if backend.Backend.LogResponse {
			log.WithFields(log.Fields{
				"user":    authedUser,
				"backend": backend.Backend,
				"link":    link.id,
				"data":    string(data),
			}).Info("audit:resp")
		}
	} else {
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
			"user":    authedUser,
			"backend": backend.Backend,
			"link":    link.id,
			"data":    strings.Join(strs, " "),
		}).Info("audit:req")
	}
}
