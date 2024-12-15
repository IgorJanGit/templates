import os
import asyncio
from octokit import Octokit
from octokit.webhook import verify


class GithubService:
    def __init__(self):
        print("Initializing GithubService...")
        # Initialize the Octokit client with authentication
        self.octokit = Octokit(auth="token", token=os.getenv("GITHUB_TOKEN"))
        print("GithubService Initialized.")

    async def verify_webhook(self, req):
        """
        Verifies the GitHub webhook signature.

        :param req: The HTTP request containing the webhook payload and headers
        :return: True if the webhook signature is valid, False otherwise
        """
        print("Verifying Webhook...")
        signature = req.headers.get("X-Hub-Signature-256")

        if not isinstance(signature, str):
            print("Webhook signature is invalid.")
            return False

        print(f"Webhook signature: {signature}")

        secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        result = await verify(
            headers=req.headers, 
            payload=req.bodyBinary,  # The body should be in binary format
            secret=secret,
            events=["push"]
        )
        print(f"Webhook verification result: {result}")
        return result

    def is_issue_opened_event(self, req):
        """
        Checks if the request is for an 'issues' event with an 'opened' action.

        :param req: The HTTP request
        :return: True if the event is an 'issues' opened event, False otherwise
        """
        print("Checking if it's an 'issues' opened event...")
        result = (
            req.headers.get("X-GitHub-Event") == "issues" and
            req.json.get("issue") and
            req.json.get("action") == "opened"
        )
        print(f"Is issue opened event: {result}")
        return result

    async def post_comment(self, repository, issue, comment):
        """
        Posts a comment on a GitHub issue.

        :param repository: The repository object
        :param issue: The issue object
        :param comment: The comment to post
        """
        print(f"Posting comment on issue {issue['number']}...")
        await self.octokit.issues.create_comment(
            owner=repository["owner"]["login"],
            repo=repository["name"],
            issue_number=issue["number"],
            body=comment
        )
        print(f"Comment posted on issue {issue['number']}.")


# Example Mock Request
class MockRequest:
    def __init__(self, headers, body_json):
        self.headers = headers
        self.bodyJson = body_json
        self.bodyBinary = str(body_json).encode('utf-8')  # Convert JSON to binary for signature verification

# Main function to test the class
async def main():
    # Create an instance of GithubService
    github_service = GithubService()

    # Simulate a mock GitHub request (for testing purposes)
    mock_req = MockRequest(
        headers={"X-Hub-Signature-256": "valid_signature", "X-GitHub-Event": "issues"},
        body_json={"action": "opened", "issue": {"number": 1}}
    )

    # Verify Webhook
    webhook_verified = await github_service.verify_webhook(mock_req)
    print(f"Webhook Verified: {webhook_verified}")

    # Check if issue is opened
    issue_opened = github_service.is_issue_opened_event(mock_req)
    print(f"Issue Opened: {issue_opened}")

    # Post a comment on the issue
    repository = {"owner": {"login": "test_user"}, "name": "test_repo"}
    issue = {"number": 1}
    comment = "This is a test comment."
    await github_service.post_comment(repository, issue, comment)
    print(f"Comment posted on issue {issue['number']}.")


if __name__ == "__main__":
    print("Starting the Github Service test...")
    # Explicitly running the main function in an event loop
    asyncio.get_event_loop().run_until_complete(main())
