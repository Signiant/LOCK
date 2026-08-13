from threading import Thread


def run_threads(iterable, target, *additional_args):
    threads = []
    for member in iterable:
        args = [member]
        args.extend(list(additional_args))
        thread_name = f"{next(iter(member))} ({target.__name__})"
        thread = Thread(target=target, args=args, name=thread_name)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
