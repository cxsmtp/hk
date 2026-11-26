import "../../ftr-settings.css";

import { notFound } from "next/navigation";

import { AppShell } from "@/components/app-shell";
import { GuideArticle, GuidePage } from "@/components/guide/guide-view";
import { GUIDE_TOPICS, guideTopic } from "@/lib/guide";

/** Every topic is a page of its own, made when the console is built. */
export function generateStaticParams() {
  return GUIDE_TOPICS.map((topic) => ({ topic: topic.slug }));
}

export const dynamicParams = false;

/** Settings → Guide → one topic (lib/guide/topics), with the contents on the left. */
export default async function GuideTopicPage({ params }: { params: Promise<{ topic: string }> }) {
  const { topic: slug } = await params;
  const topic = guideTopic(slug);
  if (!topic) notFound();
  return (
    <AppShell>
      <GuidePage current={topic.slug}>
        <GuideArticle topic={topic} />
      </GuidePage>
    </AppShell>
  );
}
