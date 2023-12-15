from crypto_pkg.clis import cli


def main():
    cli.app(prog_name='crypto')
    cli.app.add_typer()
