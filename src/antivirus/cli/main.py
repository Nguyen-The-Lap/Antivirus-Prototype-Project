""
Command-line interface for the Advanced Antivirus Scanner.
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional

from colorama import Fore, Style, init

from antivirus.core.engine import AdvancedAntivirusEngine
from antivirus.core.config import (
    MONITORED_DIRS,
    MAX_SCAN_THREADS,
    SCAN_ARCHIVES,
    LOG_LEVEL,
)
from antivirus.utils.helpers import is_admin, get_system_info, human_readable_size

# Initialize colorama
init(autoreset=True)

class AntivirusCLI:
    """Command-line interface for the antivirus scanner.
    
    This class handles command-line argument parsing and execution of
    the corresponding actions.
    """
    
    def __init__(self):
        self.engine = AdvancedAntivirusEngine()
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser with all subcommands and options."""
        parser = argparse.ArgumentParser(
            description="Advanced Antivirus Scanner",
            epilog="Example: antivirus scan /path/to/scan -r -v"
        )
        
        # Global arguments
        parser.add_argument(
            "-v", "--verbose",
            action="count",
            default=0,
            help="increase output verbosity"
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(dest="command", help="command to execute")
        
        # Scan command
        scan_parser = subparsers.add_parser(
            "scan",
            help="scan files or directories"
        )
        scan_parser.add_argument(
            "target",
            nargs="?",
            default=".",
            help="file or directory to scan (default: current directory)"
        )
        scan_parser.add_argument(
            "-r", "--recursive",
            action="store_true",
            help="scan directories recursively"
        )
        scan_parser.add_argument(
            "-t", "--threads",
            type=int,
            default=MAX_SCAN_THREADS,
            help=f"number of threads to use (default: {MAX_SCAN_THREADS})"
        )
        scan_parser.add_argument(
            "--no-archives",
            action="store_false",
            dest="scan_archives",
            default=SCAN_ARCHIVES,
            help="don't scan inside archive files"
        )
        
        # Monitor command
        monitor_parser = subparsers.add_parser(
            "monitor",
            help="monitor directories for changes"
        )
        monitor_parser.add_argument(
            "directories",
            nargs="*",
            default=MONITORED_DIRS,
            help=f"directories to monitor (default: {MONITORED_DIRS})"
        )
        
        # Quarantine commands
        quarantine_parser = subparsers.add_parser(
            "quarantine",
            help="manage quarantined files"
        )
        quarantine_subparsers = quarantine_parser.add_subparsers(dest="quarantine_command")
        
        # Quarantine list
        quarantine_list = quarantine_subparsers.add_parser(
            "list",
            help="list quarantined files"
        )
        
        # Quarantine restore
        quarantine_restore = quarantine_subparsers.add_parser(
            "restore",
            help="restore a file from quarantine"
        )
        quarantine_restore.add_argument(
            "file_id",
            help="ID of the file to restore"
        )
        
        # Quarantine delete
        quarantine_delete = quarantine_subparsers.add_parser(
            "delete",
            help="delete a file from quarantine"
        )
        quarantine_delete.add_argument(
            "file_id",
            help="ID of the file to delete"
        )
        
        # Update command
        update_parser = subparsers.add_parser(
            "update",
            help="update virus signatures"
        )
        update_parser.add_argument(
            "--force",
            action="store_true",
            help="force update even if not needed"
        )
        
        # Status command
        status_parser = subparsers.add_parser(
            "status",
            help="show scanner status"
        )
        
        return parser
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI with the given arguments.
        
        Args:
            args: Command-line arguments. If None, uses sys.argv[1:].
            
        Returns:
            int: Exit code (0 for success, non-zero for errors).
        """
        if args is None:
            args = sys.argv[1:]
        
        if not args:
            self.parser.print_help()
            return 0
            
        parsed_args = self.parser.parse_args(args)
        
        # Set log level based on verbosity
        if parsed_args.verbose >= 2:
            import logging
            logging.basicConfig(level=logging.DEBUG)
        
        # Check for admin/root privileges
        if not is_admin():
            print(f"{Fore.YELLOW}Warning: Running without administrator/root privileges. Some features may not work correctly.{Style.RESET_ALL}")
        
        # Execute the appropriate command
        if not parsed_args.command:
            self.parser.print_help()
            return 1
            
        command = parsed_args.command.lower()
        
        try:
            if command == "scan":
                return self._handle_scan(parsed_args)
            elif command == "monitor":
                return self._handle_monitor(parsed_args)
            elif command == "quarantine":
                return self._handle_quarantine(parsed_args)
            elif command == "update":
                return self._handle_update(parsed_args)
            elif command == "status":
                return self._handle_status(parsed_args)
            else:
                print(f"{Fore.RED}Error: Unknown command '{command}'{Style.RESET_ALL}")
                self.parser.print_help()
                return 1
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return 130  # SIGINT exit code
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
            if parsed_args.verbose > 0:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_scan(self, args) -> int:
        """Handle the scan command."""
        target = Path(args.target).absolute()
        
        if not target.exists():
            print(f"{Fore.RED}Error: Target '{target}' does not exist{Style.RESET_ALL}")
            return 1
        
        print(f"{Fore.CYAN}Starting scan of: {target}{Style.RESET_ALL}")
        print(f"Threads: {args.threads}, Recursive: {args.recursive}, Scan archives: {args.scan_archives}")
        
        # Start the scan
        results = self.engine.scan(
            str(target),
            recursive=args.recursive,
            scan_archives=args.scan_archives,
            max_threads=args.threads
        )
        
        # Display results
        self._display_scan_results(results)
        return 0
    
    def _handle_monitor(self, args) -> int:
        """Handle the monitor command."""
        print(f"{Fore.CYAN}Starting directory monitoring...{Style.RESET_ALL}")
        print("Press Ctrl+C to stop monitoring")
        
        try:
            self.engine.start_monitoring(args.directories)
            return 0
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            self.engine.stop_monitoring()
            return 0
    
    def _handle_quarantine(self, args) -> int:
        """Handle quarantine subcommands."""
        if not args.quarantine_command:
            print("Please specify a quarantine command (list, restore, delete)")
            return 1
        
        if args.quarantine_command == "list":
            return self._list_quarantine()
        elif args.quarantine_command == "restore":
            return self._restore_quarantine(args.file_id)
        elif args.quarantine_command == "delete":
            return self._delete_quarantine(args.file_id)
        else:
            print(f"{Fore.RED}Error: Unknown quarantine command '{args.quarantine_command}'{Style.RESET_ALL}")
            return 1
    
    def _handle_update(self, args) -> int:
        """Handle the update command."""
        print(f"{Fore.CYAN}Updating virus signatures...{Style.RESET_ALL}")
        
        try:
            results = self.engine.update_signatures(force=args.force)
            
            if results['yara']['updated']:
                print(f"{Fore.GREEN}✓ YARA rules updated: {results['yara']['message']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}ℹ {results['yara']['message']}{Style.RESET_ALL}")
            
            if results['hashes']['updated']:
                print(f"{Fore.GREEN}✓ Hash database updated: {results['hashes']['message']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}ℹ {results['hashes']['message']}{Style.RESET_ALL}")
            
            return 0
        except Exception as e:
            print(f"{Fore.RED}Error updating signatures: {e}{Style.RESET_ALL}")
            return 1
    
    def _handle_status(self, args) -> int:
        """Handle the status command."""
        system_info = get_system_info()
        
        print(f"{Fore.CYAN}=== Antivirus Status ==={Style.RESET_ALL}")
        print(f"Version: {self.engine.version}")
        print(f"System: {system_info['system']} {system_info['release']} ({system_info['machine']})")
        print(f"Python: {system_info['python_version']}")
        print(f"CPU Cores: {system_info['cpu_count']}")
        
        # Signature status
        print(f"\n{Fore.CYAN}=== Signatures ==={Style.RESET_ALL}")
        print(f"YARA Rules: {len(self.engine.yara_rules.rules) if self.engine.yara_rules else 'Not loaded'}")
        print(f"Known Hashes: {len(self.engine.hash_db)}")
        
        # Quarantine status
        quarantine_size = sum(f.stat().st_size for f in Path('data/quarantine').rglob('*') if f.is_file())
        quarantine_count = sum(1 for _ in Path('data/quarantine').rglob('*') if f.is_file())
        
        print(f"\n{Fore.CYAN}=== Quarantine ==={Style.RESET_ALL}")
        print(f"Files: {quarantine_count}")
        print(f"Size: {human_readable_size(quarantine_size)}")
        
        # Memory usage
        import psutil
        process = psutil.Process()
        mem_info = process.memory_info()
        
        print(f"\n{Fore.CYAN}=== Memory Usage ==={Style.RESET_ALL}")
        print(f"RSS: {human_readable_size(mem_info.rss)}")
        print(f"VMS: {human_readable_size(mem_info.vms)}")
        
        return 0
    
    def _display_scan_results(self, results: list) -> None:
        """Display scan results in a formatted table."""
        if not results:
            print(f"{Fore.GREEN}No threats found!{Style.RESET_ALL}")
            return
        
        # Count threats by type
        threat_counts = {}
        for result in results:
            if result.is_infected:
                threat_type = result.threat_type or 'Unknown'
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Print summary
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        print(f"Files scanned: {len(results)}")
        print(f"Threats found: {sum(threat_counts.values())}")
        
        if threat_counts:
            print("\nThreats by type:")
            for threat_type, count in sorted(threat_counts.items()):
                print(f"  {threat_type}: {count}")
            
            # Print details of infected files
            print(f"\n{Fore.RED}=== Infected Files ==={Style.RESET_ALL}")
            for result in results:
                if result.is_infected:
                    print(f"\n{Fore.RED}File: {result.file_path}{Style.RESET_ALL}")
                    print(f"Threat: {result.threat_name} ({result.threat_type})")
                    if result.details:
                        print(f"Details: {result.details}")
        else:
            print(f"\n{Fore.GREEN}No threats detected!{Style.RESET_ALL}")
    
    def _list_quarantine(self) -> int:
        """List quarantined files."""
        quarantine_dir = Path('data/quarantine')
        if not quarantine_dir.exists() or not any(quarantine_dir.iterdir()):
            print("No files in quarantine.")
            return 0
        
        print(f"{Fore.CYAN}=== Quarantined Files ==={Style.RESET_ALL}")
        print(f"{'ID':<36}  {'Date':<20}  {'Size':>10}  {'Original Path'}")
        print("-" * 80)
        
        for item in quarantine_dir.rglob('*'):
            if item.is_file():
                # Extract metadata from filename or use a metadata file
                print(f"{item.stem}  {item.stat().st_mtime}  {human_readable_size(item.stat().st_size)}  {item.name}")
        
        return 0
    
    def _restore_quarantine(self, file_id: str) -> int:
        """Restore a file from quarantine."""
        print(f"Restoring file with ID: {file_id}")
        # Implementation would go here
        return 0
    
    def _delete_quarantine(self, file_id: str) -> int:
        """Delete a file from quarantine."""
        print(f"Deleting file with ID: {file_id}")
        # Implementation would go here
        return 0


def main() -> int:
    """Main entry point for the CLI."""
    cli = AntivirusCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
