// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf/migrate"
)

func init() {
	bpfCmd.AddCommand(bpfMigrateMapsCmd)
	bpfMigrateMapsCmd.Flags().StringVarP(&start, "start", "s", "", "ELF file to start migrating maps for")
	bpfMigrateMapsCmd.Flags().StringVarP(&end, "end", "e", "", "ELF file to finalize migrating maps for")
	bpfMigrateMapsCmd.Flags().IntVarP(&rc, "return", "r", 0, "return code of the iproute2 command(s) executed between start and end")
}

// bpfMigrateMapsCmd represents the migrate command
var (
	start string
	end   string
	rc    int

	bpfMigrateMapsCmd = &cobra.Command{
		Use:    "migrate-maps",
		Hidden: true,
		Short:  "(hidden) Migrate an ELF file's map pins on bpffs",
		Long: `
Migrate an ELF file's map pins on bpffs to :pending if the new map spec's
properties differ from the map that's currently pinned.

Use '-s <elf_file>' to re-pin any maps. Then, run any iproute2 commands
to load the new ELFs. Finish up by calling '-e <elf_file> -r <iproute_return_code>'.
If the return code is non-zero, the :pending maps will be moved back to their
original locations. If the return code is 0, the :pending maps will be unpinned.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Only allow one of start or end parameters.
			if start == "" && end == "" {
				return errors.New("either s or e must be a valid filepath")
			}
			if start != "" && end != "" {
				return fmt.Errorf("s (%q) and e (%q) cannot be both set", start, end)
			}

			if start != "" {
				if err := migrate.Start(start); err != nil {
					return fmt.Errorf("error starting map migration for %q: %v", start, err)
				}
			}

			if end != "" {
				if err := migrate.Finish(end, rc != 0); err != nil {
					return fmt.Errorf("error finalizing map migration for %q: %v", end, err)
				}
			}

			return nil
		},
	}
)
