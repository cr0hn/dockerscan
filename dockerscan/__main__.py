def main():
    import os
    import sys

    if sys.version_info < (3, 5,):
        print("To run dockerscan you Python 3.5+")
        sys.exit(0)

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(1, parent_dir)
    import dockerscan

    __package__ = str("dockerscan")

    # Run the cmd
    from dockerscan.actions.cli import cli

    cli()

if __name__ == "__main__":  # pragma no cover
    main()
