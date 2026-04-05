"""Command-line entry for the password strength analyzer."""

# Import the annotations feature to allow for forward-referencing type hints
from __future__ import annotations

# Import argparse for handling command-line arguments and options
import argparse
# Import sys to access system-specific parameters and functions like exit and streams
import sys
# Import Path from pathlib for object-oriented filesystem path manipulation
from pathlib import Path

# Import custom exception classes for specific error handling throughout the application
from errors import DataGuardError, InputError, ValidationError
# Import formatting helpers for terminal coloring and report generation
from formatter import colorize, stream_supports_color, write_report
# Import the core logic function 'run' that processes the password analysis
from password_checker import run


# Define a dictionary mapping password strength grades to specific terminal color names
GRADE_COLORS = {
    "Terrible": "red",
    "Weak": "red",
    "Fair": "yellow",
    "Strong": "green",
    "Fortress": "green",
}


# Define a function to apply ANSI color codes to the 'Grade:' line of the output text
def colorize_grade_line(text: str, *, color_enabled: bool) -> str:
    # If the output stream doesn't support color or NO_COLOR is set, return text as-is
    if not color_enabled:
        return text
    # Split the multi-line output string into individual lines for processing
    lines = text.splitlines()
    # Initialize an empty list to store the processed lines
    out: list[str] = []
    # Define the specific string prefix we are looking for to apply color
    prefix = "Grade: "
    # Iterate through every line in the provided text
    for line in lines:
        # Check if the current line starts with our target prefix
        if line.startswith(prefix):
            # Extract the actual grade value (e.g., 'Strong') by removing the prefix
            grade = line[len(prefix) :].strip()
            # Look up the corresponding color for the extracted grade from our map
            color = GRADE_COLORS.get(grade)
            # If a color is found, wrap the grade string in ANSI color escape sequences
            if color:
                line = f"{prefix}{colorize(grade, color, True)}"
        # Append the (potentially modified) line to our output list
        out.append(line)
    # Rejoin the lines back into a single string separated by newlines
    return "\n".join(out)


# Define a function to configure and parse the command-line interface (CLI) flags
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    # Create the main ArgumentParser object with a description of the tool
    parser = argparse.ArgumentParser(
        description="Score passwords with layered rules (length, diversity, dictionary, patterns, entropy).",
    )
    # Create a group where exactly one of the arguments (password or file) must be provided
    src = parser.add_mutually_exclusive_group(required=True)
    # Add an option to accept a single password string directly from the terminal
    src.add_argument(
        "--password",
        "-p",
        metavar="TEXT",
        help="Analyze one password (masked in output unless --show).",
    )
    # Add an option to accept a path to a file containing multiple passwords
    src.add_argument(
        "--file",
        "-f",
        type=Path,
        metavar="PATH",
        help="Batch mode: read one password per non-empty line.",
    )
    # Add a flag to toggle the visibility of the actual passwords in the output report
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show real passwords in output instead of masking.",
    )
    # Add an option to set a custom minimum length requirement for the scoring logic
    parser.add_argument(
        "--min-length",
        type=int,
        default=8,
        metavar="N",
        help="Minimum length target for scoring (default: 8).",
    )
    # Add a flag to disable checking against the built-in common passwords list
    parser.add_argument(
        "--no-dictionary",
        action="store_true",
        help="Skip the built-in common-password dictionary check.",
    )
    # Add a flag to skip the mathematical entropy estimation calculation
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Skip entropy calculation.",
    )
    # Add an option to save the final analysis results as a JSON file at the specified path
    parser.add_argument(
        "--export",
        type=Path,
        metavar="PATH",
        help="Write the full report as JSON to this path.",
    )
    # Add an option to manually set the 'Source' metadata field in the final report
    parser.add_argument(
        "--source-name",
        default=None,
        metavar="LABEL",
        help="Metadata label for the report (default: file path or <cli --password>).",
    )
    # Parse the arguments from the provided list (or sys.argv) and return the namespace
    return parser.parse_args(argv)


# Define logic to determine the process exit code based on the password grades found
def exit_code_from_result(result: dict) -> int:
    # Iterate through each individual password analysis stored in the result dictionary
    for analysis in result.get("analyses") or []:
        # If any password is graded as 'Terrible' or 'Weak', return exit code 1 (failure)
        if analysis.get("grade") in {"Terrible", "Weak"}:
            return 1
    # If all passwords meet the 'Fair' or better threshold, return exit code 0 (success)
    return 0


# Define the high-level main function to orchestrate the application flow and handle errors
def main(argv: list[str] | None = None) -> int:
    try:
        # Attempt to execute the implementation logic
        return _main_impl(argv)
    # Catch custom validation errors (e.g., invalid min-length) and print to stderr
    except ValidationError as exc:
        print(f"password_checker: {exc}", file=sys.stderr)
        return 2
    # Catch input/output errors (e.g., file not found) and print to stderr
    except InputError as exc:
        print(f"password_checker: {exc}", file=sys.stderr)
        return 2
    # Catch general application logic errors and print to stderr
    except DataGuardError as exc:
        print(f"password_checker: {exc}", file=sys.stderr)
        return 2


# Define the core implementation of the CLI logic
def _main_impl(argv: list[str] | None = None) -> int:
    # Parse the command-line arguments into a usable object
    args = parse_args(argv)
    # Ensure that the minimum length provided is a positive integer
    if args.min_length < 1:
        raise ValidationError("--min-length must be at least 1")

    # Determine if the standard output stream supports ANSI colors
    stdout_color = stream_supports_color(sys.stdout)

    # Branch logic based on whether a single password or a file was provided
    if args.password is not None:
        # For a single password, the bulk input text is empty (password passed in config)
        input_text = ""
        # Set a default label indicating the password came from the command line
        default_source = "<cli --password>"
        # Construct the configuration dictionary for the analyzer engine
        config: dict = {
            "show_password": args.show,
            "min_length": args.min_length,
            "no_dictionary": args.no_dictionary,
            "no_entropy": args.no_entropy,
            "source_name": args.source_name or default_source,
            "single_password": args.password,
        }
    else:
        # Attempt to read the entire content of the provided file
        try:
            input_text = args.file.read_text(encoding="utf-8")
        # Catch errors if the file cannot be opened or read
        except OSError as exc:
            raise InputError(f"cannot read {args.file}: {exc}") from exc
        # Resolve the absolute path of the file to use as a default source label
        default_source = str(args.file.resolve())
        # Construct the configuration dictionary for batch file processing
        config = {
            "show_password": args.show,
            "min_length": args.min_length,
            "no_dictionary": args.no_dictionary,
            "no_entropy": args.no_entropy,
            "source_name": args.source_name or default_source,
        }

    # Pass the inputs and config to the analyzer logic and receive a results dictionary
    result = run(input_text, config)
    # Extract the primary human-readable output string from the result
    primary = result.get("output", "")
    # If the output is for a single password (starts with 'Password:'), apply coloring
    if primary.startswith("Password:"):
        primary = colorize_grade_line(primary, color_enabled=stdout_color)
    # Write the primary analysis output to standard output
    sys.stdout.write(primary)
    # Ensure the output ends with a newline for clean terminal display
    if primary and not primary.endswith("\n"):
        sys.stdout.write("\n")
    # Flush the buffer to ensure output appears immediately
    sys.stdout.flush()

    # Generate and write the summary report to standard error (stderr)
    write_report(
        result,
        report_format="text",
        # Check if stderr supports color (independent of stdout)
        color_enabled=stream_supports_color(sys.stderr),
        # Passing None for report_file sends the output directly to the stream
        report_file=None,
    )

    # If the user requested a JSON export, write the results to the specified path
    if args.export is not None:
        try:
            write_report(
                result,
                report_format="json",
                # JSON files should never contain ANSI color codes
                color_enabled=False,
                report_file=str(args.export),
            )
        # Catch errors if the export path is not writable
        except OSError as exc:
            raise InputError(f"cannot write {args.export}: {exc}") from exc

    # Calculate and return the final exit code based on the findings
    return exit_code_from_result(result)


# The entry point of the script when executed directly from the command line
if __name__ == "__main__":
    # Call the main function and exit the process with the returned integer status code
    raise SystemExit(main())