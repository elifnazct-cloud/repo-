FROM ruby:3.3-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libsqlite3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile ./
RUN bundle install
COPY . .
ENV HOST=0.0.0.0 PORT=10000
EXPOSE 10000
CMD ["bundle", "exec", "ruby", "server.rb"]
