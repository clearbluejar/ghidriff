import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';
import Link from '@docusaurus/Link';

const FeatureList = [
  {
    title: 'Command Line',
    Svg: require('@site/static/icons/terminal.svg').default,
    description: (
      <>
        A command-line binary diffing engine with a fresh take on diffing workflow and results. <code>ghidriff</code> offers quick and efficient patch diffing.
        It reduces the the complete diffing workflow (import, analysis, diffing, results) to a single step.
      </>
    ),
    // Whether you <code>pip install ghidriff</code> or leverage its <Link to={'https://github.com/clearbluejar/ghidriff/pkgs/container/ghidriff/158782097?tag=latest'}>Docker image</Link>,
    //you will quickly be diffing complex binaries. The results are available immediately to review, share, or post.
  },
  {
    title: 'Powered by Ghidra',
    Svg: require('@site/static/icons/ghidra.svg').default,
    description: (
      <>
        It leverages the power of Ghidra's ProgramAPI and <Link to={'https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html'}>FlatProgramAPI</Link> to find the added, deleted, and modified functions of two binaries.
      </>
    ),
  },
  {
    title: 'Social Diffing',
    Svg: require('@site/static/icons/markdown.svg').default,
    description: (
      <>
        The diffing results are stored in JSON and rendered in markdown (optionally side-by-side HTML).
        The markdown output promotes "social" diffing, as results are easy to publish in a gist or include in your next writeup or blog post.
      </>
    ),
  },
];

function Feature({ Svg, title, description }) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
