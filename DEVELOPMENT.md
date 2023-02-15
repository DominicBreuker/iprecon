# Development

This is only for folks who want to get set up for development.

## Getting started

Clone the repository and `cd` to it.
Now install all development dependencies:

```
python -m pip install iprecon[dev]
```

Install yourself a local version of `iprecon` with:

```
python -m pip install -e .
```

You can now modify the source code within your repository.
Assuming pip installed into a place you have in your path,
just run `iprecon` in your shell and it will use the development version.

## Tests

There are a handful of unit tests in [the tests folder](./tests).
Run them with `pytest` and keep them green.

