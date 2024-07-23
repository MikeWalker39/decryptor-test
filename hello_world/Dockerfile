FROM public.ecr.aws/lambda/python:3.12

RUN dnf -y download gnupg2-full && \
    rpm -e gnupg2-minimal --nodeps && \
    dnf -y install gnupg2-full && \
    rm -f gnupg2*.rpm

COPY app.py requirements.txt ./

RUN python3.12 -m pip install -r requirements.txt -t .

# Command can be overwritten by providing a different command in the template directly.
CMD ["app.lambda_handler"]
