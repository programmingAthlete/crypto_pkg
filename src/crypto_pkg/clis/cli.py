import typer

from crypto_pkg.clis.attacks import app as attacks

app = typer.Typer(pretty_exceptions_show_locals=False, no_args_is_help=True)
app.add_typer(attacks, name='attacks')
