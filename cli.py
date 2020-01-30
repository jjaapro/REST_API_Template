import app
import sys, getopt


def main(argv):
    production = False
    optlist, args = getopt.getopt(argv, 'p', ['production'])
    for o, a in optlist:
        if o in ('--production', '-p'):
            production = bool(a)
    app.cli(production)


if __name__ == '__main__':
    main(sys.argv[1:])
