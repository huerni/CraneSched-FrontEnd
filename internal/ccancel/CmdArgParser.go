/**
 * Copyright (c) 2023 Peking University and Peking University
 * Changsha Institute for Computing and Digital Economy
 *
 * CraneSched is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of
 * the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package ccancel

import (
	"CraneFrontEnd/internal/util"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"

	"github.com/spf13/cobra"
)

var (
	FlagJobName        string
	FlagPartition      string
	FlagState          string
	FlagAccount        string
	FlagUserName       string
	FlagNodes          []string
	FlagConfigFilePath string

	RootCmd = &cobra.Command{
		Use:   "ccancel [OPTIONS...] [job_id[,job_id...]]",
		Short: "cancel pending or running jobs",
		Long:  "",
		Args: func(cmd *cobra.Command, args []string) error {
			err := cobra.MaximumNArgs(1)(cmd, args)
			if err != nil {
				return err
			}

			if len(args) == 0 &&
				FlagJobName == "" &&
				FlagPartition == "" &&
				FlagState == "" &&
				FlagAccount == "" &&
				FlagUserName == "" &&
				FlagNodes == nil {
				log.Error("at least one condition should be given")
				os.Exit(util.ErrorCmdArg)
			}

			if len(args) > 0 {
				matched, _ := regexp.MatchString(`^([1-9][0-9]*)(,[1-9][0-9]*)*$`, args[0])
				if !matched {
					log.Error("job id list must follow the format " +
						"<job_id> or '<job_id>,<job_id>,<job_id>...'")
					os.Exit(util.ErrorCmdArg)
				}
			}

			return nil
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			config := util.ParseConfig(FlagConfigFilePath)
			stub = util.GetStubToCtldByConfig(config)
		},
		Run: func(cmd *cobra.Command, args []string) {
			// args was checked by cobra.ExactArgs(1)
			// len(args)=1 here.
			if err := CancelTask(args); err != util.ErrorSuccess {
				os.Exit(err)
			}
		},
	}
)

func ParseCmdArgs() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(util.ErrorExecuteFailed)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&FlagConfigFilePath, "config", "C",
		util.DefaultConfigPath, "Path to configuration file")
	RootCmd.Flags().StringVarP(&FlagJobName, "name", "n", "",
		"cancel jobs only with the job name")
	RootCmd.Flags().StringVarP(&FlagPartition, "partition", "p", "",
		"cancel jobs jobs only in the Partition")
	RootCmd.Flags().StringVarP(&FlagState, "state", "t", "",
		"cancel jobs of the State. "+
			"Valid job states are PENDING(PD), RUNNING(R). "+
			"job states are case-insensitive")
	RootCmd.Flags().StringVarP(&FlagAccount, "account", "A", "",
		"cancel jobs under an account")
	RootCmd.Flags().StringVarP(&FlagUserName, "user", "u", "",
		"cancel jobs run by the user")
	RootCmd.Flags().StringSliceVarP(&FlagNodes, "nodes", "w", nil,
		"cancel jobs running on the nodes")
}
