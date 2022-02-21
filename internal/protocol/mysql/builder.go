package mysql

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func PacketResolve(data []byte) string {
	var builder strings.Builder
	packets := DeserializePacket(data)
	for _, packet := range packets {
		switch packet.GetCommandType() {
		case COM_INIT_DB:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(ComInitDb).SchemaName))
		case COM_QUERY:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(ComQuery).Query))
		case COM_FIELD_LIST:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(ComFieldList).Table))
		case COM_CREATE_DB:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(ComCreateDb).SchemaName))
		case COM_DROP_DB:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(ComDropDb).SchemaName))
		case COM_REFRESH:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(packet.(ComRefresh).SubCommand)))
		case COM_SHUTDOWN:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(packet.(ComShutdown).SubCommand)))
		case COM_PROCESS_KILL:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), strconv.Itoa(packet.(ComProcessKill).ConnectionID)))
		case COM_CHANGE_USER:
			user := packet.(ComChangeUser)
			data, _ := json.Marshal(map[string]interface{}{
				"auth_plugin_name": user.AuthPluginName,
				"auth_response":    user.AuthResponse,
				"character_set":    user.CharacterSet,
				"schema":           user.SchemaName,
				"user":             user.User,
				"data":             user.Data,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_BINLOG_DUMP:
			pack := packet.(ComBinlogDump)
			data, _ := json.Marshal(map[string]interface{}{
				"binlog_file_name": pack.BinlogFileName,
				"binlog_position":  pack.BinlogPosition,
				"server_id":        pack.ServerID,
				"flag":             pack.Flag,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_TABLE_DUMP:
			pack := packet.(ComTableDump)
			data, _ := json.Marshal(map[string]interface{}{
				"database": pack.DatabaseName,
				"table":    pack.TableName,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_REGISTER_SLAVE:
			pack := packet.(ComRegisterSlave)
			data, _ := json.Marshal(map[string]interface{}{
				"master_id":        pack.MasterID,
				"replication_rank": pack.ReplicationRank,
				"server_id":        pack.ServerID,
				"slave_hostname":   pack.SlavesHostName,
				"slave_mysql_port": pack.SlavesMySQLPort,
				"slave_user":       pack.SlavesUser,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_STMT_PREPARE:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), packet.(ComSTMTPrepare).Query))
		case COM_STMT_EXECUTE:
			pack := packet.(ComSTMTExecute)
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
		case COM_STMT_SEND_LONG_DATA:
			pack := packet.(ComSTMTSendLongData)
			data, _ := json.Marshal(map[string]interface{}{
				"statement_id": pack.StatementID,
				"param_id":     pack.ParamID,
				"data":         pack.Data,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_STMT_CLOSE:
			pack := packet.(ComSTMTClose)
			data, _ := json.Marshal(map[string]interface{}{
				"statement_id": pack.StatementID,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_STMT_RESET:
			pack := packet.(ComSTMTReset)
			data, _ := json.Marshal(map[string]interface{}{
				"statement_id": pack.StatementID,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_SET_OPTION:
			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(packet.(ComSetOption).ComSetOptionOperation)))
		case COM_STMT_FETCH:
			pack := packet.(ComSTMTFetch)
			data, _ := json.Marshal(map[string]interface{}{
				"stmtid":   pack.STMTID,
				"num_rows": pack.NumRows,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_BINLOG_DUMP_GTID:
			pack := packet.(ComBinlogDumpGTID)
			data, _ := json.Marshal(map[string]interface{}{
				"flags":           pack.Flags,
				"server_id":       pack.ServerID,
				"binlog_filename": pack.BinlogFilename,
				"binlog_position": pack.BinlogPosition,
				"data":            pack.Data,
			})

			builder.WriteString(fmt.Sprintf("%s: %s\n", string(packet.GetCommandType()), string(data)))
		case COM_RESET_CONNECTION:
		case COM_SLEEP:
		case COM_QUIT:
		case COM_DEBUG:
		case COM_PING:
		case COM_TIME:
		case COM_DELAYED_INSERT:
		case COM_STATISTICS:
		case COM_PROCESS_INFO:
		case COM_CONNECT:
		case COM_CONNECT_OUT:
		case COM_DAEMON:
		}

	}

	return strings.Trim(builder.String(), "\n\r ")
}
