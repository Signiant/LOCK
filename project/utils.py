from threading import Thread


def run_threads(iterable, target, *additional_args):
    threads = []
    for member in iterable:
        args = [member]
        args.extend(list(additional_args))
        thread = Thread(target=target, args=args)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
