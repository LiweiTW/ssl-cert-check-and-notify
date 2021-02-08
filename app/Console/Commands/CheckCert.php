<?php

namespace App\Console\Commands;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\File;

class CheckCert extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'cert:check {channel}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check ssl cert expire time.';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $channel = $this->argument('channel');

        $result = [];
        $content = File::get(env("FILE_PATH", "./storage/app/domain.list"));
        $domainList = explode("\n", $content);

        foreach ($domainList as $domain) {
            if ($domain) {
                $contextCreate = stream_context_create(array("ssl" => array("capture_peer_cert" => true)));
                $res = stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $contextCreate);
                $context = stream_context_get_params($res);
                $certInfo = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
                $now = Carbon::now();
                $expiredTimeValue = $certInfo["validTo_time_t"] ?? null;
                $expiredTime = Carbon::createFromTimestamp($expiredTimeValue);
                $leftDays = $now->diffInDays($expiredTime);

                $result[] = [
                    "domain" => $domain,
                    "expiredTime" => $expiredTime->toDateString(),
                    "leftDays" => $leftDays,
                ];
            } else {
                continue;
            }
        }


        switch ($channel) {
            case "teams":
                foreach ($result as $message) {
                    $URI = env("TEAMS_WEBHOOK");
                    $client = new Client();
                    $response = $client->post($URI, [RequestOptions::JSON => [
                        "title" => $message["domain"] ?? "" . " - SSL cert expired date check",
                        "text" => "**{$message["leftDays"]}** day(s) left. Expired at {$message["expiredTime"]}",
                    ]]);
                }
                break;
            default:
                break;
        }

        return 0;
    }
}
